import os
import sys

from simplemfs import MFSVolume
import utils

if __name__ == "__main__":
    if len(sys.argv) > 1:
        mfs_img_file = os.path.abspath(sys.argv[1])
    else:
        print('Please specify a MSF image to continue.')
        exit(1);

    with open(mfs_img_file, 'rb') as mfs_file:
        mfs_vol = MFSVolume(mfs_file)
        if mfs_vol.list_files() == 0:
            exit(1)

        file_num = 0
        while file_num == 0:
            print("Please enter file number to extract resource fork from:")
            inp_str = input("> ")
            flag,file_num = utils.str_to_int(inp_str)
            if not flag:
                file_num = 0
            if not mfs_vol.get_fork_size(file_num, 1):
                file_num = 0

        print("Please enter file name to write data to:")
        file_name = input("> ")

        with open(file_name, 'wb') as dst_file:
            data = mfs_vol.read_fork(file_num, 1,
                mfs_vol.get_fork_size(file_num, 1), pos=0)
            dst_file.write(data)
