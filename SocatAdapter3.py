#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *

PARSER_MEMORY_LENGTH = 8
EXPECTED_PREAMBLE = [0, 0, 8, 0]
EXPECTED_PREAMBLE_LENGTH = len(EXPECTED_PREAMBLE)

class SocatParser:
	def __init__(self):
		self.memory = []
		self.this_packet = []
		self.packet_length = 0
		self.inPacket = False
	
	def addByte(self, net_byte):
		self.memory.append(net_byte)
		self.memory = self.memory[-1*PARSER_MEMORY_LENGTH:]
		if len(self.memory) < PARSER_MEMORY_LENGTH:
			return None
		
		if (self.memory[0:EXPECTED_PREAMBLE_LENGTH] == EXPECTED_PREAMBLE) and not self.inPacket:
			self.packet_length = 256*self.memory[6] + self.memory[7]
			self.inPacket = True
			for bt in self.memory[4:]:
				self.this_packet.append(bt)
		
		elif self.inPacket:
			self.this_packet.append(net_byte)
			if len(self.this_packet) == self.packet_length:
				pkt = IP(bytes(self.this_packet))
				self.this_packet = []
				self.packet_length = 0
				self.inPacket = False
				return pkt


def socat_format(pkt):
	return bytes(EXPECTED_PREAMBLE) + bytes(pkt)
