''' Various utility functions. '''
from datetime import datetime
import struct

def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n

def align(n, m):
    return (n + m - 1) & bit_not(m - 1)

def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

def fourcc_to_bytes(fourcc):
    res = bytearray()
    for i in range(4):
        res.append((fourcc >> (24 - i * 8)) & 0xFF)
    return bytes(res)

def str_to_int(str):
    try:
        result = int(str, 0)
        return True,result
    except ValueError:
        return False,0

def unpack_pstr(bin_data):
    '''
    Unpack a pascal string from binary data and return a Python string.
    '''
    str_len = bin_data[0]
    fmt_str = '%ip' % (str_len + 1)
    return struct.unpack(fmt_str, bin_data[0:str_len+1])[0].decode('mac_roman')

HFS_TO_EPOCH = 2082844800

def mactime_to_str(timestamp):
    return datetime.fromtimestamp(timestamp - HFS_TO_EPOCH) \
        .strftime('%Y-%m-%d %H:%M:%S')
