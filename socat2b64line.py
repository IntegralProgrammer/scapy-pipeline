#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import base64

from scapy.all import *
from SocatAdapter import SocatParser


parser_obj = SocatParser()
while True:
	byte = sys.stdin.read(1)
	ret = parser_obj.addByte(ord(byte))
	if ret is not None:
		sys.stdout.write(base64.b64encode(str(ret)))
		sys.stdout.write('\n')
		sys.stdout.flush()
