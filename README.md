# Forensics-Tools
In this project, I implemented some forensics tools for Network, Disk, File, and Process Analysic using popular forensics libraries and frameworks (e.g. Tshark, SleuthKit, Volatility).

NatDetector.py
--------------
A simple python script, by invoking tshark, prints the IPs that are likely natted using the TCP timestamp option. Usage: **python NatDetector.py <pcap_file>**

SlackFinder.py
--------------
A script that, using SleuthKit, checks all the sector slack at the end of each file in a ext3 partition and dumps the ones that contain data. For each file that has data in the slack space, the script creates a file in a subdirectory named with the inode number and containing the slack bytes. Usage: **python SlackFinder <ext3_image_file> [output_directory]**

TypeDetector.py
--------------
A python script to detect camouflaged files. The script uses the python magic bindings compare the results with the mime types (extracted from /etc/mime.types by default or by a file specified as parameter)
The script takes as input a directory and recursively analyze its content. Usage: **python TypeDetector.py <directory> [magic_file]**

ProcessComparatory.py
--------------
A tool accepts as parameters two snapshot taken from the same machine at different times (e.g., 15 minutes one after the other) and for each processes (uniquely identified by its PID), list the number of pages that are different between the two snapshots. Usage: **python ProcessComparatory.py <snapshot1> <snapshot2> <profile_name>**
