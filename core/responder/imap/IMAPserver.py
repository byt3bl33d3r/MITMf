import logging
import threading

from SocketServer import TCPServer, ThreadingMixIn, BaseRequestHandler
from IMAPPackets import *
from core.responder.common import *
from core.logger import logger

formatter = logging.Formatter("%(asctime)s [IMAPserver] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("IMAPserver", formatter)

class IMAPserver():

	def start(self):
		try:
			log.debug("online")
			server = ThreadingTCPServer(("0.0.0.0", 143), IMAP)
			t = threading.Thread(name="IMAPserver", target=server.serve_forever)
			t.setDaemon(True)
			t.start()
		except Exception as e:
			log.error("Error starting on port {}: {}".format(143, e))

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
				log.info('IMAP Credentials from {}. ("User" "Pass"): {}'.format(self.client_address[0],Credentials))
				self.request.send(str(ditchthisconnection()))
				data = self.request.recv(1024)

		except Exception as e:
			log.error("Error handling request: {}".format(e))
