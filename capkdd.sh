#!/bin/bash

for i in {1..2}
do
	/usr/sbin/tcpdump -n -i eth0 -c 100 -K -U --immediate-mode -w - | /usr/bin/bro --pseudo-realtime -C -r - darpa2gurekddcup.bro | /usr/bin/sort -n | /home/blake/trafAld /dev/stdin | /usr/bin/cut -d " " -f 7- -s --output-delimiter=","
done