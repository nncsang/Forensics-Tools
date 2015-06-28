__author__ = 'nncsang'

# --------------------------------------------------------------------------------------------- #
# Some parts of this code is borrowed from https://github.com/SokratisVidros/slack_pytsk.
# Function find_slack, main are my own contributions
# --------------------------------------------------------------------------------------------- #

import pytsk3
import shutil
import os
import sys

from progressbar import Bar, ProgressBar, Percentage
from pytsk3 import *

DEBUG = 0
BLOCK_SIZE = 0
FS = None

FILE_TYPE_LOOKUP = {
    TSK_FS_NAME_TYPE_UNDEF: '-',
    TSK_FS_NAME_TYPE_FIFO: 'p',
    TSK_FS_NAME_TYPE_CHR: 'c',
    TSK_FS_NAME_TYPE_DIR: 'd',
    TSK_FS_NAME_TYPE_BLK: 'b',
    TSK_FS_NAME_TYPE_REG: 'r',
    TSK_FS_NAME_TYPE_LNK: 'l',
    TSK_FS_NAME_TYPE_SOCK: 'h',
    TSK_FS_NAME_TYPE_SHAD: 's',
    TSK_FS_NAME_TYPE_WHT: 'w',
    TSK_FS_NAME_TYPE_VIRT: 'v'
}

META_TYPE_LOOKUP = {
    TSK_FS_META_TYPE_REG: 'r',
    TSK_FS_META_TYPE_DIR: 'd',
    TSK_FS_META_TYPE_FIFO: 'p',
    TSK_FS_META_TYPE_CHR: 'c',
    TSK_FS_META_TYPE_BLK: 'b',
    TSK_FS_META_TYPE_LNK: 'h',
    TSK_FS_META_TYPE_SHAD: 's',
    TSK_FS_META_TYPE_SOCK: 's',
    TSK_FS_META_TYPE_WHT: 'w',
    TSK_FS_META_TYPE_VIRT: 'v'
}

NTFS_TYPES_TO_PRINT = [
    TSK_FS_ATTR_TYPE_NTFS_IDXROOT,
    TSK_FS_ATTR_TYPE_NTFS_DATA,
    TSK_FS_ATTR_TYPE_DEFAULT,
]

FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])


def hex_pp(src, length=8):
    N = 0
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        s = s.translate(FILTER)
        result += "%04X %-*s %s\n" % (N, length * 3, hexa, s)
        N += length
    return result

def find_slack(inode):
    f = FS.open_meta(inode)

    size = f.info.meta.size
    l_d_size = size % BLOCK_SIZE
    l_block = (int(size / BLOCK_SIZE)) * BLOCK_SIZE
    s_size = BLOCK_SIZE - l_d_size
    slack_bytes = []

    if l_d_size == 0:
        return (("").join([chr(int(b, 16)) for b in slack_bytes]), len(slack_bytes))


    data = f.read_random(l_block + l_d_size, s_size, TSK_FS_ATTR_TYPE_DEFAULT, 0, TSK_FS_FILE_READ_FLAG_SLACK)

    output = []
    i = 0

    # Remove all heading 0s
    while i < len(data) and ord(data[i]) == 00:
        i += 1

    while i < len(data):
        output.append(data[i])
        i += 1

    if len(output) > 0:
        slack_bytes.extend(["%02x" % ord(c) for c in output])
        f = open(output_dir + "/" + str(inode), 'w+')
        f.write(("").join([chr(int(b, 16)) for b in slack_bytes]))
        f.flush()
        f.close()


def is_fs_directory(f):
    return FILE_TYPE_LOOKUP.get(int(f.info.name.type), '-') == FILE_TYPE_LOOKUP[TSK_FS_NAME_TYPE_DIR]


def is_fs_regfile(f):
    return FILE_TYPE_LOOKUP.get(int(f.info.name.type), '-') == FILE_TYPE_LOOKUP[TSK_FS_NAME_TYPE_REG]


def scan_inode(f):
    meta = f.info.meta
    name = f.info.name
    inode = f.info.meta.addr

    name_type = '-'
    if name:
        name_type = FILE_TYPE_LOOKUP.get(int(name.type), '-')

    meta_type = '-'
    if meta:
        meta_type = META_TYPE_LOOKUP.get(int(meta.type), '-')

    type = "%s/%s" % (name_type, meta_type)
    slack_data = ''

    if (is_fs_regfile(f)):
        list_file.append(inode)


def list_directory(directory, stack=None):
    stack.append(directory.info.fs_file.meta.addr)
    for f in directory:
        scan_inode(f)
        if (is_fs_directory(f)):
            try:
                d = f.as_directory()
                inode = f.info.meta.addr
                if inode not in stack:
                    list_directory(d, stack)
            except:
                pass

    stack.pop(-1)


# --------------------------------------------------------------------------------------------- #
# Check parameters
# --------------------------------------------------------------------------------------------- #

# Default output directory
output_dir = "output_slack_space"

if (len(sys.argv) < 2 or len(sys.argv) > 3):
    print("Usage: SlackFinder <ext3_image_file> [output_directory]")
    exit()

if len(sys.argv) == 3:
    output_dir = sys.argv[2]

# Delete output_dir and all its contents if it is exist
try:
    shutil.rmtree(output_dir)

except OSError:
    pass

# Create output_dir
os.makedirs(output_dir)

# --------------------------------------------------------------------------------------------- #
# Read fs image and some useful infos
# --------------------------------------------------------------------------------------------- #
img = pytsk3.Img_Info(sys.argv[1])
FS = pytsk3.FS_Info(img)

BLOCK_SIZE = FS.info.block_size

# Traverse through all directory and store all found files into list_file
directory = FS.open_dir("/")
list_file = []
list_directory(directory, [])

count = 0
pbar = ProgressBar(widgets=[Percentage(), Bar()], maxval=len(list_file)).start()

# Traverse through all files to find slack spaces
for inode in list_file:
    count += 1
    pbar.update(count)
    find_slack(inode)
pbar.finish()

print('Checking ' + output_dir + ' for the output')
