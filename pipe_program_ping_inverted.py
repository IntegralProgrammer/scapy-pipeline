#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import base64

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
			
			sys.stderr.write("Should reply with: {} -- {}\n".format(reply_pkt.summary(), base64.b64encode(str(reply_pkt[ICMP].payload))))
			
			#Flip the payload bits
			payload_str = str(reply_pkt[ICMP].payload)
			inv_payload_str = ""
			for i in range(len(payload_str)):
				inv_payload_str += chr((ord(payload_str[i]) ^ 0xff) & 0xff)
			reply_pkt[ICMP].payload = Raw(inv_payload_str)
			
			sys.stderr.write("Tx: {} -- {}\n".format(reply_pkt.summary(), base64.b64encode(str(reply_pkt[ICMP].payload))))
			
			#Send it over to Socat
			sys.stdout.write(socat_format(reply_pkt))
			sys.stdout.flush()
		
		sys.stderr.write("\n")
