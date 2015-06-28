__author__ = 'nncsang'
from magic import Magic
import magic
import sys
import os
import re
import mimetypes

def print_result(filename, real_ext, expected_ext):
    print("{:35s} \t {:10s} \t {:20s}".format(filename, real_ext, expected_ext))


# Default mime.types files
magic_file = "/etc/mime.types"
directory = None

# --------------------------------------------------------------------------------------------- #
# Check parameters
# --------------------------------------------------------------------------------------------- #
if (len(sys.argv) == 3):
    magic_file = sys.argv[2]
elif (len(sys.argv) == 2):
    pass
else:
    print("Usage: TypeDetector.py <directory> [magic_file]")
    exit(0)


directory = sys.argv[1]
type_maps = {}

# --------------------------------------------------------------------------------------------- #
# Parse mime.types
# --------------------------------------------------------------------------------------------- #
try:
    f = open(magic_file, "r")
    for line in f:
        if (len(line) == ""):
            continue

        if (line[0] == '#'):
            continue

        line = re.sub(r'\s+', '\t', line)

        parts = line.split("\t")

        type, ext = parts[0], parts[1:]
        type_maps[type] = ext
except:
    print("Cannot read " + magic_file)
    exit(0)


print("{:35s} \t {:10s} \t {:20s}".format('Camouflaged file', 'Claimed ext', 'Expected ext'))
# --------------------------------------------------------------------------------------------- #
# For each file:
#   + Get claimed ext
#   + Using magic and mime.types to find out expected exts
# --------------------------------------------------------------------------------------------- #

mg = Magic(mime=True, mime_encoding=False, keep_going=True, uncompress=False)
for folder, subs, files in os.walk(directory):
    for filename in files:
        try:
            full_path = folder + "//" + filename
            detected_type = str(mg.from_file(full_path).decode("utf-8"))
            ext = os.path.splitext(filename)[1][1:]
            expected_exts = type_maps[detected_type]
            if (ext != "" and ext not in expected_exts):
                # Print out highly likely camouflaged files
                print_result(full_path, ext, "".join([b + " " for b in expected_exts]))
        except:
            pass
