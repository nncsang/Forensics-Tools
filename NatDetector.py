import sys
import subprocess
from datetime import datetime

# --------------------------------------------------------------------------------------------- #
# The RFC suggests that the scale a should be chosen between 0.001 (one tick per
# second) and 1 (one tick per millisecond)
# --------------------------------------------------------------------------------------------- #
MAX_STICK_PER_MICROSECOND = 0.001

# --------------------------------------------------------------------------------------------- #
# Maximum delay in microsecond
# --------------------------------------------------------------------------------------------- #
MAX_DIFF = 500000

# --------------------------------------------------------------------------------------------- #
# Check parameters
# --------------------------------------------------------------------------------------------- #
if len(sys.argv) != 2:
	print("Usage: NatDetector.py <pcap_file>")
	exit(0)

nw_entities = {}

# Read all TCP packets
cmd = 'tshark -n -r ' + sys.argv[1] + ' -Y "tcp" -t e -T fields -e frame.time_epoch -e ip.src -e tcp.options.timestamp.tsval'
proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


for packet_str in proc.stdout.readlines():

	# Parse console's output
	packet_fields = packet_str.split('\t')
	sniff_time = datetime.fromtimestamp(float(packet_fields[0]))
	ip = packet_fields[1]
	tsval = int(packet_fields[2])

	if ip in nw_entities:
		# Only consider not natted packets
		if not nw_entities[ip]['natted']:

			prev_tsval = int(nw_entities[ip]['tsval'])
			# --------------------------------------------------------------------------------------------- #
			# Special case
			# --------------------------------------------------------------------------------------------- #
			if prev_tsval > tsval:
				nw_entities[ip]['natted'] = True
				print(ip)
				continue

			# --------------------------------------------------------------------------------------------- #
			# Computing estimated tsval bases on:
			#	+ time_diff = sniff_time_2 - sniff_time_1
			#	+ tsval2 = tsval_1 + time_diff * MAX_STICK_PER_MICROSECOND
			# --------------------------------------------------------------------------------------------- #
			dd = sniff_time - nw_entities[ip]['sniff_time']
			dd = prev_tsval + int(dd.microseconds * MAX_STICK_PER_MICROSECOND)
			dd = abs(dd - tsval)

			# --------------------------------------------------------------------------------------------- #
			# Compare difference between real tsval and estimated tsval 									
			# If it's greater than MAX_DIFF ==> highly likely it's natted							
			# --------------------------------------------------------------------------------------------- #
			if dd > MAX_DIFF:
				nw_entities[ip]['natted'] = True
				print(ip)
			else:
				# Update information for next comparasion
				nw_entities[ip]['sniff_time'] = sniff_time
				nw_entities[ip]['tsval'] = tsval
	else:
		# Create new entry in dictionary
		nw_entities[ip] = dict(natted=False, sniff_time=sniff_time, \
								tsval=tsval)



