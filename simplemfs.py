'''
Python module for reading and writing Macintosh File System volume images.
'''
from hlstruct import Structure
from macfiles import Point, FInfo
import utils

import os
import struct
import sys

SECT_SIZE    = 512
MDB_START    = SECT_SIZE * 2
MIN_MFS_SIZE = SECT_SIZE * 4 # minimum MFS size (2 boot sectors + 2 MDB sectors)
BLK_MAP_BITS = 12            # number of bits in one block map entry
DSK_CPY_SIZE = 84            # newer Disk Copy (4.2) image contains an extra header

MFS_VOL_SIG  = 0xD2D7   # MFS volume signature

class MDBRec(Structure):
    '''
    Binary description of the MFS Master Directory Block record.
    '''
    _fields_ = [
        ('>H', 'drSigWord' ),
        ( 'I', 'drCrDate'  ),
        ( 'I', 'drLsBkUp'  ),
        ( 'H', 'drAtrb'    ),
        ( 'H', 'drNmFls'   ),
        ( 'H', 'drDirSt'   ),
        ( 'H', 'drBlLen'   ),
        ( 'H', 'drNmAlBlks'),
        ( 'I', 'drAlBlkSiz'),
        ( 'I', 'drClpSiz'  ),
        ( 'H', 'drAlBlSt'  ),
        ( 'I', 'drNxtFNum' ),
        ( 'H', 'drFreeBks' )
    ]

class MFSFileDirRec(Structure):
    '''
    Binary description of the MFS File Directory entry.
    '''
    _fields_ = [
        ('B',   'flFlags' ),
        ('B',   'flTyp'   ),
        (FInfo, 'flUsrWds'),
        ('>I',  'flFlNum' ),
        ('H',   'flStBlk' ),
        ('I',   'flLgLen' ),
        ('I',   'flPyLen' ),
        ('H',   'flRStBlk'),
        ('I',   'flRLgLen'),
        ('I',   'flRPyLen'),
        ('I',   'flCrDat' ),
        ('I',   'flMdDat' )
    ]

class MFSVolume:
    def __init__(self, img_file):
        self._img_file  = img_file
        self._img_size  = self._get_image_size()
        self._mfs_offs  = 0
        self._mdb_rec   = None
        self._bmap_size = 0
        self._bmap_data = None
        self._files     = {}
        self._load_vol_info()

    def _get_image_size(self):
        self._img_file.seek(0, os.SEEK_END)
        size = self._img_file.tell()
        self._img_file.seek(0, os.SEEK_SET)
        return size

    def _check_mfs_sig(self, offset=0):
        self._img_file.seek(MDB_START + offset, os.SEEK_SET)
        sig = struct.unpack('>H', self._img_file.read(2))[0]
        if sig == MFS_VOL_SIG:
            return True
        else:
            return False

    def _read_mdb_rec(self):
        self._img_file.seek(MDB_START + self._mfs_offs, os.SEEK_SET)
        self._mdb_rec = MDBRec.from_file(self._img_file)
        print(self._img_file.tell())
        self._vol_name = utils.unpack_pstr(self._img_file.read(28))

    def _print_mdb_rec(self):
        print("Volume signature: %s" % hex(self._mdb_rec.drSigWord))
        print("Created at %s" % utils.mactime_to_str(self._mdb_rec.drCrDate))
        print("Last backup at %s" % utils.mactime_to_str(self._mdb_rec.drLsBkUp))
        print("Number of files: %d" % self._mdb_rec.drNmFls)
        print("File directory start: %d" % self._mdb_rec.drDirSt)
        print("File directory length: %d" % self._mdb_rec.drBlLen)
        print("Number of alloc blocks: %d" % self._mdb_rec.drNmAlBlks)
        print("Alloc block size: %d" % self._mdb_rec.drAlBlkSiz)
        print("Clump size: %d" % self._mdb_rec.drClpSiz)
        print("Alloc block start: %d" % self._mdb_rec.drAlBlSt)
        print("Volume name: %s" % self._vol_name)
        print("")

    def _load_block_map(self):
        if self._mdb_rec == None:
            return
        num_blocks = self._mdb_rec.drNmAlBlks
        if num_blocks == 0:
            print("Invalid number of allocation blocks: %d" % num_blocks)
            return
        self._bmap_size = utils.align(num_blocks * BLK_MAP_BITS, 8) // 8

        pbm_data = self._img_file.read(self._bmap_size)

        # uncompress block map data
        self._bmap_data = []
        for i in range(num_blocks):
            bit_pos  = i * BLK_MAP_BITS
            byte_pos = bit_pos >> 3
            if bit_pos & 7:
                bme = ((pbm_data[byte_pos] & 0xF) << 8) | pbm_data[byte_pos + 1]
            else:
                bme = (pbm_data[byte_pos] << 4) | ((pbm_data[byte_pos+1] >> 4) & 0xF)
            self._bmap_data.append(bme)
            if bme == 0xFFF:
                print("Extra file directory block #%d found!" % i)

    def _read_file_dir(self):
        if self._mdb_rec.drNmFls <= 0:
            print("This MFS volume is empty.")
            return

        dir_sect = self._mdb_rec.drDirSt
        self._img_file.seek(dir_sect * SECT_SIZE + self._mfs_offs)

        for fn in range(self._mdb_rec.drNmFls):
            if not ((self._img_file.read(1)[0]) & 0x80):
                # Moving to next file directory sector
                dir_sect += 1
                if (dir_sect - self._mdb_rec.drDirSt) > self._mdb_rec.drBlLen:
                    print("File directory exhausted!")
                    return
                self._img_file.seek(dir_sect * SECT_SIZE + self._mfs_offs)
            else:
                # move file position one byte back
                self._img_file.seek(-1, os.SEEK_CUR)

            file_entry = MFSFileDirRec.from_file(self._img_file)

            # read file name
            name_len = self._img_file.read(1)[0] # read string length
            # move file position one byte back
            self._img_file.seek(-1, os.SEEK_CUR)
            file_name = utils.unpack_pstr(self._img_file.read(name_len + 1))

            if file_entry.flFlNum in self._files:
                print("Duplicate file number: ", file_entry.flFlNum)
            else:
                self._files.update({file_entry.flFlNum : (file_entry, file_name)})

            if self._img_file.tell() & 1:
                self._img_file.read(1)[0] # align file pos to a word boundary

    def _get_file_blocks(self, start_block):
        blocks = []
        cur_block = start_block
        while cur_block != 1:
            next_block = self._bmap_data[cur_block - 2]
            if next_block < 1 or next_block > 0xFFE:
                print("Invalid block map value %d", next_block)
                return []
            blocks.append(cur_block)
            cur_block = next_block
        return blocks

    def get_fork_size(self, file_num, fork):
        if file_num not in self._files:
            print("File %d not found" % file_num)
            return 0

        file = self._files[file_num]
        if fork == 0:
            return file[0].flLgLen
        else:
            return file[0].flRLgLen

    def read_fork(self, file_num, fork, nbytes, pos=0):
        if file_num not in self._files:
            print("File %d not found" % file_num)
            return None

        file = self._files[file_num]

        if fork == 0:
            start_block = file[0].flStBlk
            fork_length = file[0].flLgLen
        else:
            start_block = file[0].flRStBlk
            fork_length = file[0].flRLgLen

        if start_block == 0:
            print("Specified fork is empty")
            return None

        blocks = self._get_file_blocks(start_block)
        if (len(blocks) * self._mdb_rec.drAlBlkSiz) < fork_length:
            print("Inconsistent fork length vs number of allocaton blocks!")
            return None

        data = bytearray()

        block_size = self._mdb_rec.drAlBlkSiz
        blocks_offset = self._mdb_rec.drAlBlSt * SECT_SIZE - 2 * block_size

        while nbytes > 0:
            block_pos = pos % block_size
            chunk_size = min(block_size - block_pos, nbytes)
            file_pos = blocks[pos // block_size] * block_size + blocks_offset + block_pos
            self._img_file.seek(file_pos + self._mfs_offs, os.SEEK_SET)
            data.extend(self._img_file.read(chunk_size))
            pos += chunk_size
            nbytes -= chunk_size

        return data

    def _load_vol_info(self):
        if self._img_size < MIN_MFS_SIZE:
            print("Image file too small")
            return False
        if not self._check_mfs_sig():
            if not self._check_mfs_sig(offset=DSK_CPY_SIZE):
                print("No MFS volume found")
                return False
            else:
                self._mfs_offs = DSK_CPY_SIZE
        self._read_mdb_rec()
        if self._mdb_rec.drSigWord != MFS_VOL_SIG:
            print("Bad MFS signature")
            return False
        self._load_block_map()
        self._read_file_dir()
        return True

    def list_files(self):
        if not self._files:
            print("This volume appears to be empty.")
            return 0

        for fn, file in self._files.items():
            print("File #%d:" % fn)
            print("\tName:", file[1])
            print("\tCreated at:", utils.mactime_to_str(file[0].flCrDat))
            print("\tType:", utils.fourcc_to_bytes(file[0].flUsrWds.fdType))
            print("\tCreator:", utils.fourcc_to_bytes(file[0].flUsrWds.fdCreator))
            print("\tData fork length:", file[0].flLgLen)
            print("\tResource fork length:", file[0].flRLgLen)
            print("")

        return len(self._files)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        mfs_img_file = os.path.abspath(sys.argv[1])
    else:
        print('Please specify a MSF image to continue.')
        exit(1);

    with open(mfs_img_file, 'rb') as mfs_file:
        mfs_vol = MFSVolume(mfs_file)
        mfs_vol._print_mdb_rec() # just for testing
        mfs_vol.list_files()
        mfs_vol.read_fork(4, 1, nbytes=16, pos=0)
