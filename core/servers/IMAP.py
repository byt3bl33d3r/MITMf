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
import os
import core.responder.settings as settings
import threading

from core.responder.utils import *
from SocketServer import BaseRequestHandler, ThreadingMixIn, TCPServer
from core.responder.packets import IMAPGreeting, IMAPCapability, IMAPCapabilityEnd

class IMAP:

	def start(self):
		try:
			if OsInterfaceIsSupported():
				server = ThreadingTCPServer((settings.Config.Bind_To, 143), IMAP4)
			else:
				server = ThreadingTCPServer(('', 143), IMAP4)

			t = threading.Thread(name='IMAP', target=server.serve_forever)
			t.setDaemon(True)
			t.start()
		except Exception as e:
			print "Error starting IMAP server: {}".format(e)
			print_exc()

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    
    allow_reuse_address = 1

    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To+'\0')
            except:
                pass
        TCPServer.server_bind(self)

# IMAP4 Server class
class IMAP4(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(IMAPGreeting()))
			data = self.request.recv(1024)

			if data[5:15] == "CAPABILITY":
				RequestTag = data[0:4]
				self.request.send(str(IMAPCapability()))
				self.request.send(str(IMAPCapabilityEnd(Tag=RequestTag)))
				data = self.request.recv(1024)

			if data[5:10] == "LOGIN":
				Credentials = data[10:].strip()

				SaveToDb({
					'module': 'IMAP', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': Credentials[0], 
					'cleartext': Credentials[1], 
					'fullhash': Credentials[0]+":"+Credentials[1],
				})

				## FIXME: Close connection properly
				## self.request.send(str(ditchthisconnection()))
				## data = self.request.recv(1024)

		except Exception:
			pass