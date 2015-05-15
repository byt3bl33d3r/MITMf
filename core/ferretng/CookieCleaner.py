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
import string

class CookieCleaner:
    '''This class cleans cookies we haven't seen before.  The basic idea is to
    kill sessions, which isn't entirely straight-forward.  Since we want this to
    be generalized, there's no way for us to know exactly what cookie we're trying
    to kill, which also means we don't know what domain or path it has been set for.

    The rule with cookies is that specific overrides general.  So cookies that are
    set for mail.foo.com override cookies with the same name that are set for .foo.com,
    just as cookies that are set for foo.com/mail override cookies with the same name
    that are set for foo.com/

    The best we can do is guess, so we just try to cover our bases by expiring cookies
    in a few different ways.  The most obvious thing to do is look for individual cookies
    and nail the ones we haven't seen coming from the server, but the problem is that cookies are often
    set by Javascript instead of a Set-Cookie header, and if we block those the site
    will think cookies are disabled in the browser.  So we do the expirations and whitlisting
    based on client,server tuples.  The first time a client hits a server, we kill whatever
    cookies we see then.  After that, we just let them through.  Not perfect, but pretty effective.

    '''

    _instance = None

    def __init__(self):
        self.cleanedCookies = set();
        self.enabled        = False

    @staticmethod
    def getInstance():
        if CookieCleaner._instance == None:
            CookieCleaner._instance = CookieCleaner()

        return CookieCleaner._instance

    def setEnabled(self, enabled):
        self.enabled = enabled

    def isClean(self, method, client, host, headers):
        if method == "POST":             return True
        if not self.enabled:             return True
        if not self.hasCookies(headers): return True
        
        return (client, self.getDomainFor(host)) in self.cleanedCookies

    def getExpireHeaders(self, method, client, host, headers, path):
        domain = self.getDomainFor(host)
        self.cleanedCookies.add((client, domain))

        expireHeaders = []

        for cookie in headers['cookie'].split(";"):
            cookie                 = cookie.split("=")[0].strip()            
            expireHeadersForCookie = self.getExpireCookieStringFor(cookie, host, domain, path)            
            expireHeaders.extend(expireHeadersForCookie)
        
        return expireHeaders

    def hasCookies(self, headers):
        return 'cookie' in headers        

    def getDomainFor(self, host):
        hostParts = host.split(".")
        return "." + hostParts[-2] + "." + hostParts[-1]

    def getExpireCookieStringFor(self, cookie, host, domain, path):
        pathList      = path.split("/")
        expireStrings = list()
        
        expireStrings.append(cookie + "=" + "EXPIRED;Path=/;Domain=" + domain + 
                             ";Expires=Mon, 01-Jan-1990 00:00:00 GMT\r\n")

        expireStrings.append(cookie + "=" + "EXPIRED;Path=/;Domain=" + host + 
                             ";Expires=Mon, 01-Jan-1990 00:00:00 GMT\r\n")

        if len(pathList) > 2:
            expireStrings.append(cookie + "=" + "EXPIRED;Path=/" + pathList[1] + ";Domain=" +
                                 domain + ";Expires=Mon, 01-Jan-1990 00:00:00 GMT\r\n")

            expireStrings.append(cookie + "=" + "EXPIRED;Path=/" + pathList[1] + ";Domain=" +
                                 host + ";Expires=Mon, 01-Jan-1990 00:00:00 GMT\r\n")
        
        return expireStrings

    
