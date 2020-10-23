'''
Python module for reading and writing Macintosh File System volume images.
'''
from hlstruct import Structure
import utils

import os
import struct
import sys

SECT_SIZE    = 512
MDB_START    = SECT_SIZE * 2
MIN_MFS_SIZE = SECT_SIZE * 4 # minimum MFS size (2 boot sectors + 2 MDB sectors)
BLK_MAP_BITS = 12            # number of bits in one block map entry

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

class Point(Structure):
    _fields_ = [
        ('>H', 'x'),
        ('H',  'y')
    ]

class FInfo(Structure):
    _fields_ = [
        ('>I',  'fdType'    ),
        ('I',   'fdCreator' ),
        ('H',   'fdFlags'   ),
        (Point, 'fdLocation'),
        ('h',   'fdFldr'    )
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

    def _read_mdb_rec(self):
        self._img_file.seek(MDB_START, os.SEEK_SET)
        self._mdb_rec = MDBRec.from_file(self._img_file)
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
        for i in range(self._mdb_rec.drNmAlBlks):
            bit_pos  = i * BLK_MAP_BITS
            byte_pos = bit_pos >> 3
            if bit_pos & 7:
                bme = ((pbm_data[byte_pos] & 3) << 8) | pbm_data[byte_pos + 1]
            else:
                bme = (pbm_data[byte_pos] << 4) | ((pbm_data[byte_pos+1] >> 4) & 3)
            self._bmap_data.append(bme)
            if bme == 0xFFF:
                print("Extra file directory block #%d found!" % i)

    def _read_file_dir(self):
        if self._mdb_rec.drNmFls <= 0:
            print("This MFS volume is empty.")
            return

        dir_sect = self._mdb_rec.drDirSt
        self._img_file.seek(dir_sect * SECT_SIZE)

        for fn in range(self._mdb_rec.drNmFls):
            if not ((self._img_file.read(1)[0]) & 0x80):
                # Moving to next file directory sector
                dir_sect += 1
                if (dir_sect - self._mdb_rec.drDirSt) > self._mdb_rec.drBlLen:
                    print("File directory exhausted!")
                    return
                self._img_file.seek(dir_sect * SECT_SIZE)
            else:
                # move file position one byte back
                self._img_file.seek(-1, os.SEEK_CUR)

            file_entry = MFSFileDirRec.from_file(self._img_file)

            #if file_entry.flRStBlk:
            #    print("Next RF sector: ", self._bmap_data[file_entry.flRStBlk - 2])

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

    def _load_vol_info(self):
        if self._img_size < MIN_MFS_SIZE:
            print("Image file too small")
            return False
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
            return

        for fn, file in self._files.items():
            print("File #%d:" % fn)
            print("\tName:", file[1])
            print("\tCreated at:", utils.mactime_to_str(file[0].flCrDat))
            print("\tType:", utils.fourcc_to_bytes(file[0].flUsrWds.fdType))
            print("\tCreator:", utils.fourcc_to_bytes(file[0].flUsrWds.fdCreator))
            print("\tData fork length:", file[0].flLgLen)
            print("\tResource fork length:", file[0].flRLgLen)
            print("")

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
