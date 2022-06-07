from hlstruct import Structure
from pathlib import Path
import utils

''' Very basic support for Mac OS file manager '''

class VCB(Structure):
    _fields_ = [
        ('>I',   'qLink'       ),
        ( 'h',   'qType'       ),
        ( 'h',   'vcbFlags'    ),
        ( 'H',   'vcbSigWord'  ),
	    ( 'I',   'vcbCrDate'   ),
	    ( 'I',   'vcbLsMod'    ),
	    ( 'h',   'vcbAtrb'     ),
        ( 'H',   'vcbNmFls'    ),
        ( 'h',   'vcbVBMSt'    ),
        ( 'h',   'vcbAllocPtr' ),
        ( 'H',   'vcbNmAlBlks' ),
        ( 'i',   'vcbAlBlkSiz' ),
        ( 'i',   'vcbClpSiz'   ),
        ( 'h',   'vcbAlBlSt'   ),
        ( 'i',   'vcbNxtCNID'  ),
        ( 'H',   'vcbFreeBks'  ),
        ( '28p', 'vcbVN'       ),
        ( 'h',   'vcbDrvNum'   ),
        ( 'h',   'vcbDRefNum'  ),
        ( 'h',   'vcbFSID'     ),
        ( 'h',   'vcbVRefNum'  ),
        ( 'I',   'vcbMAdr'     ),
        ( 'I',   'vcbBufAdr'   ),
        ( 'h',   'vcbMLen'     ),
        ( 'h',   'vcbDirIndex' ),
        ( 'h',   'vcbDirBlk'   ),
        ( 'I',   'vcbVolBkUp'  ),
        ( 'H',   'vcbVSeqNum'  ),
        ( 'i',   'vcbWrCnt'    ),
        ( 'i',   'vcbXTClpSiz' ),
        ( 'i',   'vcbCTClpSiz' ),
        ( 'H',   'vcbNmRtDirs' ),
        ( 'i',   'vcbFilCnt'   ),
        ( 'i',   'vcbDirCnt'   ),
        ( '8i',  'vcbFndrInfo' ),
        ( 'H',   'vcbVCSize'   ),
        ( 'H',   'vcbVBMCSiz'  ),
        ( 'H',   'vcbCtlCSiz'  ),
        ( 'H',   'vcbXTAlBlks' ),
        ( 'H',   'vcbCTAlBlks' ),
        ( 'h',   'vcbXTRef'    ),
        ( 'h',   'vcbCTRef'    ),
        ( 'I',   'vcbCtlBuf'   ),
        ( 'i',   'vcbDirIDM'   ),
        ( 'h',   'vcbOffsM'    )
    ]

class FCBPBRec(Structure):
    _fields_ = [
        ('>I', 'qLink'        ),
        ( 'h', 'qType'        ),
        ( 'h', 'ioTrap'       ),
        ( 'I', 'ioCmdAddr'    ),
        ( 'I', 'ioCompletion' ),
        ( 'h', 'ioResult'     ),
        ( 'I', 'ioNamePtr'    ),
        ( 'h', 'ioVRefNum'    ),
        ( 'h', 'ioRefNum'     ),
        ( 'h', 'filler'       ),
        ( 'h', 'ioFCBIndx'    ),
        ( 'h', 'filler1'      ),
        ( 'i', 'ioFCBFlNm'    ),
        ( 'h', 'ioFCBFlags'   ),
        ( 'H', 'ioFCBStBlk'   ),
        ( 'i', 'ioFCBEOF'     ),
        ( 'i', 'ioFCBPLen'    ),
        ( 'i', 'ioFCBCrPs'    ),
        ( 'h', 'ioFCBVRefNum' ),
        ( 'i', 'ioFCBClpSiz'  ),
        ( 'i', 'ioFCBParID'   )
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

class HFileParam(Structure):
    _fields_ = [
        ('>I',   'qLink'        ),
        ( 'h',   'qType'        ),
        ( 'h',   'ioTrap'       ),
        ( 'I',   'ioCmdAddr'    ),
        ( 'I',   'ioCompletion' ),
        ( 'h',   'ioResult'     ),
        ( 'I',   'ioNamePtr'    ),
        ( 'h',   'ioVRefNum'    ),
        ( 'h',   'ioFRefNum'    ),
        ( 'b',   'ioFVersNum'   ),
        ( 'b',   'filler1'      ),
        ( 'h',   'ioFDirIndex'  ),
        ( 'b',   'ioFlAttrib'   ),
        ( 'b',   'ioFlVersNum'  ),
        ( FInfo, 'ioFlFndrInfo' ),
        ( 'i',   'ioDirID'      ),
        ( 'H',   'ioFlStBlk'    ),
        ( 'i',   'ioFlLgLen'    ),
        ( 'i',   'ioFlPyLen'    ),
        ( 'H',   'ioFlRStBlk'   ),
        ( 'i',   'ioFlRLgLen'   ),
        ( 'i',   'ioFlRPyLen'   ),
        ( 'I',   'ioFlCrDat'    ),
        ( 'I',   'ioFlMdDat'    )
    ]

class MacFiles:
    def __init__(self, rt, my_file_path):
        self._rt = rt # bare68k runtime object
        self._next_fnum = 0 # next file number
        self._my_files = {} # here we're keeping track of open files

        self.init_vcbs() # initialize global array of VCBs

        self.open_file(my_file_path)

    def init_vcbs(self):
        # create a VCB for the main volume
        vcb = VCB(bytearray(VCB.struct_size))
        vcb.vcbVN = bytes('MonsterHD', 'mac-roman')
        vcb.vcbVRefNum = 0x0FFA
        vcb.vcbDRefNum = -37
        self._rt.get_mem().w_block(0x0000C000, bytes(vcb._buffer))
        self._rt.get_mem().w32(0x356, 0xC000) # initialize VCBQHdr lowmem global

    def open_file(self, my_file_path):
        ref_num = self._next_fnum * 0x5E + 2 # that's how MacOS generates RefNums
        name = Path(my_file_path).name
        print("Filename: %s" % name)
        self._my_files[ref_num] = {
            'path' : my_file_path,
            'name' : name
        }
        self._next_fnum += 1

    def set_file_name(self, ref_num, dest_addr):
        name = self._my_files[ref_num]['name']
        conv_name = utils.pack_pstr(name)
        #print(conv_name)
        self._rt.get_mem().w_block(dest_addr, conv_name)

    def hfs_func(self, selector, pb_ptr):
        if selector == 8:
            print("PBGetFCBInfoSync requested")
            # make copy of our parameter block
            pb_bin = bytearray(self._rt.get_mem().r_block(pb_ptr, FCBPBRec.struct_size))
            pb = FCBPBRec(pb_bin)
            if pb.ioFCBIndx != 0:
                print("Warning: ioFCBIndx is not 0!")
                return 0
            else:
                # catch invalid RefNums
                if pb.ioRefNum not in self._my_files:
                    return -51
                # return file name if requested
                if pb.ioNamePtr != 0:
                    self.set_file_name(pb.ioRefNum, pb.ioNamePtr)
                pb.ioFCBVRefNum = 0x0FFA
                pb.ioFCBParID = 0x0EADBEEF
                # copy modified parameter block back to the guest
                self._rt.get_mem().w_block(pb_ptr, bytes(pb._buffer))
                pb.ioResult = 0
                return 0
        else:
            print("Unsupported HFSDispatch selector %d!" % selector)

    def hget_file_info(self, pb_ptr):
        print("HFileParam size = %d" % HFileParam.struct_size)
        pb_bin = bytearray(self._rt.get_mem().r_block(pb_ptr, HFileParam.struct_size))
        pb = HFileParam(pb_bin)
        finfo = pb.ioFlFndrInfo
        finfo.fdType = 0x4150504C # 'APPL' aka application
        pb.ioFlFndrInfo =  finfo
        # copy modified parameter block back to the guest
        self._rt.get_mem().w_block(pb_ptr, bytes(pb._buffer))
        return 0
