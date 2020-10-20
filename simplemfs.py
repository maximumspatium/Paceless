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

class MFSVolume:
    def __init__(self, img_file):
        self._img_file  = img_file
        self._img_size  = self._get_image_size()
        self._mdb_rec   = None
        self._bmap_size = 0
        self._bmap_data = None
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
        print("Number of files: %d" % self._mdb_rec.drNmFls)
        print("File directory start: %d" % self._mdb_rec.drDirSt)
        print("File directory length: %d" % self._mdb_rec.drBlLen)
        print("Number of alloc blocks: %d" % self._mdb_rec.drNmAlBlks)
        print("Alloc block size: %d" % self._mdb_rec.drAlBlkSiz)
        print("Clump size: %d" % self._mdb_rec.drClpSiz)
        print("Alloc block start: %d" % self._mdb_rec.drAlBlSt)
        print("Volume name: %s" % self._vol_name)

    def _load_block_map(self):
        if self._mdb_rec == None:
            return
        num_blocks = self._mdb_rec.drNmAlBlks
        if num_blocks == 0:
            print("Invalid number of allocation blocks: %d" % num_blocks)
            return
        self._bmap_size = utils.align(num_blocks * BLK_MAP_BITS, 8) // 8
        self._bmap_data = self._img_file.read(self._bmap_size)

    def _load_vol_info(self):
        if self._img_size < MIN_MFS_SIZE:
            print("Image file too small")
            return False
        self._read_mdb_rec()
        if self._mdb_rec.drSigWord != MFS_VOL_SIG:
            print("Bad MFS signature")
            return False
        self._load_block_map()
        return True

if __name__ == "__main__":
    if len(sys.argv) > 1:
        mfs_img_file = os.path.abspath(sys.argv[1])
    else:
        print('Please specify a MSF image to continue.')
        exit(1);

    with open(mfs_img_file, 'rb') as mfs_file:
        mfs_vol = MFSVolume(mfs_file)
        mfs_vol._print_mdb_rec() # just for testing
