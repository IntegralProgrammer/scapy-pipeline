#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import base64

from scapy.all import *
from SocatAdapter3 import SocatParser, socat_format


parser_obj = SocatParser()
while True:
	byte = sys.stdin.buffer.read(1)
	ret = parser_obj.addByte(ord(byte))
	if ret is not None:
		sys.stderr.write("Rx: {}\n".format(ret.summary()))
		if ret.haslayer(ICMP):
			#Generate the reply
			reply_pkt = ret.copy()
			reply_pkt[IP].src = ret[IP].dst
			reply_pkt[IP].dst = ret[IP].src
			reply_pkt[ICMP].type = 0
			
			#Force a checksum recalculation
			del reply_pkt[IP].chksum
			del reply_pkt[ICMP].chksum
			reply_pkt = reply_pkt.__class__(bytes(reply_pkt))
			
			sys.stderr.write("Should reply with: {} -- {}\n".format(reply_pkt.summary(), base64.b64encode(bytes(reply_pkt[ICMP].payload))))
			
			#Flip the payload bits
			payload_str = bytes(reply_pkt[ICMP].payload)
			inv_payload_str = []
			for i in range(len(payload_str)):
				inv_payload_str.append((payload_str[i] ^ 0xff) & 0xff)
			reply_pkt[ICMP].payload = Raw(bytes(inv_payload_str))
			
			#Force a checksum recalculation
			del reply_pkt[IP].chksum
			del reply_pkt[ICMP].chksum
			reply_pkt = reply_pkt.__class__(bytes(reply_pkt))
			
			sys.stderr.write("Tx: {} -- {}\n".format(reply_pkt.summary(), base64.b64encode(bytes(reply_pkt[ICMP].payload))))
			
			#Send it over to Socat
			sys.stdout.buffer.write(socat_format(reply_pkt))
			sys.stdout.buffer.flush()
		
		sys.stderr.write("\n")
