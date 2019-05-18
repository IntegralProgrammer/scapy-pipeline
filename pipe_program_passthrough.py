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
		sys.stderr.write("Passing: {}\n".format(ret.summary()))
		
		#Send it over to Socat
		sys.stdout.write(socat_format(ret))
		sys.stdout.flush()
