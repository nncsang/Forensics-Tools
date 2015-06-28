__author__ = 'nncsang'

import volatility
import volatility.conf as conf
import volatility.registry as registry
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import os
import sys
import hashlib

from volatility.plugins.linux.pslist import *

class linux_pslist(linux_common.AbstractLinuxCommand):
	"""Gather active tasks by walking the task_struct->task list"""

	def __init__(self, config, *args, **kwargs):
		linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
		self._config = config

	def allprocs(self):
		linux_common.set_plugin_members(self)

		init_task_addr = self.addr_space.profile.get_symbol("init_task")
		init_task = obj.Object("task_struct", vm=self.addr_space, offset=init_task_addr)

		# walk the ->tasks list, note that this will *not* display "swapper"
		for task in init_task.tasks:
			yield task

def page_compare(page1, page2):
	if len(page1) != len(page2):
		return -1

	for byte1, byte2 in zip(page1, page2):
		if byte1 != byte2:
			return -1

	return 0

FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])

def print_result(PID, same, diff):
	print("{:^10d} \t\t {:^10d} \t\t\t {:^10d}".format(PID, same, diff))

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


# --------------------------------------------------------------------------------------------- #
# Check parameters
# --------------------------------------------------------------------------------------------- #
if len(sys.argv) != 4:
	print("Usage: ProcessComparatory.py <snapshot1> <snapshot2> <profile_name>")
	exit(0)

# --------------------------------------------------------------------------------------------- #
# Print output header
# --------------------------------------------------------------------------------------------- #
print("{:^10s} \t {:^10s} \t {:^10s}".format('PID', 'Pages that matches', 'Pages that are different'))

# --------------------------------------------------------------------------------------------- #
# Load plugins
# --------------------------------------------------------------------------------------------- #
registry.PluginImporter()
config = conf.ConfObject()
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()

# --------------------------------------------------------------------------------------------- #
# Read all processes of 2nd image and store them in PRC2
# --------------------------------------------------------------------------------------------- #
config.opts['location'] = "file://" + os.path.abspath(sys.argv[2]).replace(' ', '%20')
config.opts['profile'] = sys.argv[3]

PRC2 = {}
pslist2 = linux_pslist(config).allprocs()
for proc in pslist2:
	PRC2[proc.pid] = proc

# --------------------------------------------------------------------------------------------- #
# Read all processes of 1st image
# --------------------------------------------------------------------------------------------- #
config.opts['location'] = "file://" + os.path.abspath(sys.argv[1]).replace(' ', '%20')
pslist1 = linux_pslist(config).allprocs()


# --------------------------------------------------------------------------------------------- #
# Go through all processes of 1st image
# --------------------------------------------------------------------------------------------- #
for proc1 in pslist1:

	# Get PID
	PID = proc1.pid

	# Reset counters
	same = 0
	diff = 0

	# Image 2 has considering process
	if PRC2.has_key(PID):

		# Get process spaces
		process_space_1 = proc1.get_process_address_space()
		process_space_2 = PRC2[PID].get_process_address_space()

		# Get page lists
		page_list_1 = process_space_1.get_available_pages()
		page_list_2 = process_space_2.get_available_pages()

		# Reset dictionary
		page_hash = {}

		# Read all pages' content int page_list_1
		# Store {hash(content): (addr, size)}
		for addr, size in page_list_1:
			data = process_space_1.zread(addr, size)
			content_hash = hash(data)

			if page_hash.has_key(content_hash) == False:
				page_hash[content_hash] = []

			page_hash[content_hash].append((addr, size))

		# Go through all pages in page_list_2
		for addr, size in page_list_2:
			page2 = process_space_2.zread(addr, size)
			content_hash = hash(page2)

			same_page = False

			# Find page in page_list_1 having same hash content
			if page_hash.has_key(content_hash):

				# Check for sure two pages are the same
				for addr1, size1 in page_hash[content_hash]:
					if size1 != size:
						continue

					page1 = process_space_1.zread(addr1, size1)
					if page_compare(page1, page2) == 0:
						same += 1
						same_page = True

						# Remove found page in page_hash
						page_hash[content_hash].remove((addr1, size1))
						break

				if same_page == False:
					diff += 1
			else:
				diff += 1

		# For page that presents in page_list_1 but page_list_2
		for content_hash in page_hash.keys():
			diff += len(page_hash[content_hash])

		# Print output
		print_result(PID, same, diff)

		# Remove considering process in PRC2
		PRC2.pop(PID)

	# Image 2 doesn't has considering process
	else:

		# So number of different page equals number of page of considering process
		diff = 0
		for page in process_space_1.get_available_pages():
			diff += 1
		
		# Output result for considering process
		print_result(PID, same, diff)
		pass

# For process that presents in 2nd image but 1st image
same = 0

for PID in sorted(PRC2.keys()):
	diff = 0

	for page in PRC2[PID].get_process_address_space().get_available_pages():
			diff += 1

	print_result(PID, same, diff)
