#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import base64

from scapy.all import *
from SocatAdapter import socat_format


while True:
	line = sys.stdin.readline()
	line = line.rstrip()
	pkt = IP(base64.b64decode(line))
	sys.stdout.write(socat_format(pkt))
	sys.stdout.flush()
