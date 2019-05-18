#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from scapy.all import *
from SocatAdapter import SocatParser, socat_format


parser_obj = SocatParser()
while True:
	byte = sys.stdin.read(1)
	ret = parser_obj.addByte(ord(byte))
	if ret is not None:
		sys.stderr.write("Rx: {}\n".format(ret.summary()))
		if ret.haslayer(ICMP):
			#Generate the reply
			reply_pkt = ret.copy()
			reply_pkt[IP].src = ret[IP].dst
			reply_pkt[IP].dst = ret[IP].src
			reply_pkt[ICMP].type = 0
			sys.stderr.write("Tx: {}\n".format(reply_pkt.summary()))
			
			#Send it over to Socat
			sys.stdout.write(socat_format(reply_pkt))
			sys.stdout.flush()
