# DNSChef is a highly configurable DNS Proxy for Penetration Testers 
# and Malware Analysts. Please visit http://thesprawl.org/projects/dnschef/
# for the latest version and documentation. Please forward all issues and
# concerns to iphelix [at] thesprawl.org.

# Copyright (C) 2015 Peter Kacherginsky, Marcello Salvati
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without 
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import threading, random, operator, time
import SocketServer, socket, sys, os
import binascii
import string
import base64
import time
import logging

from configobj import ConfigObj
from core.configwatcher import ConfigWatcher
from core.utils import shutdown
from core.logger import logger

from dnslib import *
from IPy import IP

formatter = logging.Formatter("%(asctime)s %(clientip)s [DNS] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("DNSChef", formatter)

dnslog = logging.getLogger('dnslog')
handler = logging.FileHandler('./logs/dns/dns.log',)
handler.setFormatter(formatter)
dnslog.addHandler(handler)
dnslog.setLevel(logging.INFO)

# DNSHandler Mixin. The class contains generic functions to parse DNS requests and
# calculate an appropriate response based on user parameters.
class DNSHandler():

    def parse(self,data):

        nametodns      = DNSChef().nametodns
        nameservers    = DNSChef().nameservers
        hsts           = DNSChef().hsts
        hstsconfig     = DNSChef().real_records
        server_address = DNSChef().server_address
        clientip       = {"clientip": self.client_address[0]}

        response = ""
    
        try:
            # Parse data as DNS        
            d = DNSRecord.parse(data)

        except Exception as e:
            log.info("Error: invalid DNS request", extra=clientip)
            dnslog.info("Error: invalid DNS request", extra=clientip)

        else:        
            # Only Process DNS Queries
            if QR[d.header.qr] == "QUERY":  
                     
                # Gather query parameters
                # NOTE: Do not lowercase qname here, because we want to see
                #       any case request weirdness in the logs.
                qname = str(d.q.qname)
                
                # Chop off the last period
                if qname[-1] == '.': qname = qname[:-1]

                qtype = QTYPE[d.q.qtype]
                
                # Find all matching fake DNS records for the query name or get False
                fake_records = dict()

                for record in nametodns:

                    fake_records[record] = self.findnametodns(qname, nametodns[record])

                if hsts:
                    if qname in hstsconfig:
                        response = self.hstsbypass(hstsconfig[qname], qname, nameservers, d)
                        return response

                    elif qname[:4] == 'wwww':
                        response = self.hstsbypass(qname[1:], qname, nameservers, d)
                        return response

                    elif qname[:3] == 'web':
                        response = self.hstsbypass(qname[3:], qname, nameservers, d)
                        return response

                # Check if there is a fake record for the current request qtype
                if qtype in fake_records and fake_records[qtype]:

                    fake_record = fake_records[qtype]

                    # Create a custom response to the query
                    response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1, aa=1, ra=1), q=d.q)

                    log.info("Cooking the response of type '{}' for {} to {}".format(qtype, qname, fake_record), extra=clientip)
                    dnslog.info("Cooking the response of type '{}' for {} to {}".format(qtype, qname, fake_record), extra=clientip)

                    # IPv6 needs additional work before inclusion:
                    if qtype == "AAAA":
                        ipv6 = IP(fake_record)
                        ipv6_bin = ipv6.strBin()
                        ipv6_hex_tuple = [int(ipv6_bin[i:i+8],2) for i in xrange(0,len(ipv6_bin),8)]
                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](ipv6_hex_tuple)))

                    elif qtype == "SOA":
                        mname,rname,t1,t2,t3,t4,t5 = fake_record.split(" ")
                        times = tuple([int(t) for t in [t1,t2,t3,t4,t5]])

                        # dnslib doesn't like trailing dots
                        if mname[-1] == ".": mname = mname[:-1]
                        if rname[-1] == ".": rname = rname[:-1]

                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](mname,rname,times)))

                    elif qtype == "NAPTR":
                        order,preference,flags,service,regexp,replacement = fake_record.split(" ")
                        order = int(order)
                        preference = int(preference)

                        # dnslib doesn't like trailing dots
                        if replacement[-1] == ".": replacement = replacement[:-1]

                        response.add_answer( RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](order,preference,flags,service,regexp,DNSLabel(replacement))) )

                    elif qtype == "SRV":
                        priority, weight, port, target = fake_record.split(" ")
                        priority = int(priority)
                        weight = int(weight)
                        port = int(port)
                        if target[-1] == ".": target = target[:-1]

                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](priority, weight, port, target) ))

                    elif qtype == "DNSKEY":
                        flags, protocol, algorithm, key = fake_record.split(" ")
                        flags = int(flags)
                        protocol = int(protocol)
                        algorithm = int(algorithm)
                        key = base64.b64decode(("".join(key)).encode('ascii'))

                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](flags, protocol, algorithm, key) ))

                    elif qtype == "RRSIG":
                        covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig = fake_record.split(" ")
                        covered = getattr(QTYPE,covered) # NOTE: Covered QTYPE
                        algorithm = int(algorithm)
                        labels = int(labels)
                        orig_ttl = int(orig_ttl)
                        sig_exp = int(time.mktime(time.strptime(sig_exp +'GMT',"%Y%m%d%H%M%S%Z")))
                        sig_inc = int(time.mktime(time.strptime(sig_inc +'GMT',"%Y%m%d%H%M%S%Z")))
                        key_tag = int(key_tag)
                        if name[-1] == '.': name = name[:-1]
                        sig = base64.b64decode(("".join(sig)).encode('ascii'))

                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](covered, algorithm, labels,orig_ttl, sig_exp, sig_inc, key_tag, name, sig)))

                    else:
                        # dnslib doesn't like trailing dots
                        if fake_record[-1] == ".": fake_record = fake_record[:-1]
                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](fake_record)))

                    response = response.pack()

                elif qtype == "*" and not None in fake_records.values():
                    log.info("Cooking the response of type '{}' for {} with {}".format("ANY", qname, "all known fake records."), extra=clientip)
                    dnslog.info("Cooking the response of type '{}' for {} with {}".format("ANY", qname, "all known fake records."), extra=clientip)

                    response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap,qr=1, aa=1, ra=1), q=d.q)

                    for qtype,fake_record in fake_records.items():
                        if fake_record:

                            # NOTE: RDMAP is a dictionary map of qtype strings to handling classses
                            # IPv6 needs additional work before inclusion:
                            if qtype == "AAAA":
                                ipv6 = IP(fake_record)
                                ipv6_bin = ipv6.strBin()
                                fake_record = [int(ipv6_bin[i:i+8],2) for i in xrange(0,len(ipv6_bin),8)]

                            elif qtype == "SOA":
                                mname,rname,t1,t2,t3,t4,t5 = fake_record.split(" ")
                                times = tuple([int(t) for t in [t1,t2,t3,t4,t5]])

                                # dnslib doesn't like trailing dots
                                if mname[-1] == ".": mname = mname[:-1]
                                if rname[-1] == ".": rname = rname[:-1]

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](mname,rname,times)))

                            elif qtype == "NAPTR":
                                order,preference,flags,service,regexp,replacement = fake_record.split(" ")
                                order = int(order)
                                preference = int(preference)

                                # dnslib doesn't like trailing dots
                                if replacement and replacement[-1] == ".": replacement = replacement[:-1]

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](order,preference,flags,service,regexp,replacement)))

                            elif qtype == "SRV":
                                priority, weight, port, target = fake_record.split(" ")
                                priority = int(priority)
                                weight = int(weight)
                                port = int(port)
                                if target[-1] == ".": target = target[:-1]

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](priority, weight, port, target) ))

                            elif qtype == "DNSKEY":
                                flags, protocol, algorithm, key = fake_record.split(" ")
                                flags = int(flags)
                                protocol = int(protocol)
                                algorithm = int(algorithm)
                                key = base64.b64decode(("".join(key)).encode('ascii'))

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](flags, protocol, algorithm, key) ))

                            elif qtype == "RRSIG":
                                covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig = fake_record.split(" ")
                                covered = getattr(QTYPE,covered) # NOTE: Covered QTYPE
                                algorithm = int(algorithm)
                                labels = int(labels)
                                orig_ttl = int(orig_ttl)
                                sig_exp = int(time.mktime(time.strptime(sig_exp +'GMT',"%Y%m%d%H%M%S%Z")))
                                sig_inc = int(time.mktime(time.strptime(sig_inc +'GMT',"%Y%m%d%H%M%S%Z")))
                                key_tag = int(key_tag)
                                if name[-1] == '.': name = name[:-1]
                                sig = base64.b64decode(("".join(sig)).encode('ascii'))

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](covered, algorithm, labels,orig_ttl, sig_exp, sig_inc, key_tag, name, sig) ))

                            else:
                                # dnslib doesn't like trailing dots
                                if fake_record[-1] == ".": fake_record = fake_record[:-1]
                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](fake_record)))

                    response = response.pack()

                # Proxy the request
                else:
                    log.debug("Proxying the response of type '{}' for {}".format(qtype, qname), extra=clientip)
                    dnslog.info("Proxying the response of type '{}' for {}".format(qtype, qname), extra=clientip)

                    nameserver_tuple = random.choice(nameservers).split('#')               
                    response = self.proxyrequest(data, *nameserver_tuple)

        return response
    

    # Find appropriate ip address to use for a queried name. The function can 
    def findnametodns(self,qname,nametodns):

        # Make qname case insensitive
        qname = qname.lower()
    
        # Split and reverse qname into components for matching.
        qnamelist = qname.split('.')
        qnamelist.reverse()
    
        # HACK: It is important to search the nametodns dictionary before iterating it so that
        # global matching ['*.*.*.*.*.*.*.*.*.*'] will match last. Use sorting for that.
        for domain,host in sorted(nametodns.iteritems(), key=operator.itemgetter(1)):

            # NOTE: It is assumed that domain name was already lowercased
            #       when it was loaded through --file, --fakedomains or --truedomains
            #       don't want to waste time lowercasing domains on every request.

            # Split and reverse domain into components for matching
            domain = domain.split('.')
            domain.reverse()
            
            # Compare domains in reverse.
            for a,b in map(None,qnamelist,domain):
                if a != b and b != "*":
                    break
            else:
                # Could be a real IP or False if we are doing reverse matching with 'truedomains'
                return host
        else:
            return False
    
    # Obtain a response from a real DNS server.
    def proxyrequest(self, request, host, port="53", protocol="udp"):
        clientip = {'clientip': self.client_address[0]}

        reply = None
        try:
            if DNSChef().ipv6:

                if protocol == "udp":
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                elif protocol == "tcp":
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

            else:
                if protocol == "udp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                elif protocol == "tcp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(3.0)

            # Send the proxy request to a randomly chosen DNS server

            if protocol == "udp":
                sock.sendto(request, (host, int(port)))
                reply = sock.recv(1024)
                sock.close()

            elif protocol == "tcp":
                sock.connect((host, int(port)))

                # Add length for the TCP request
                length = binascii.unhexlify("%04x" % len(request)) 
                sock.sendall(length+request)

                # Strip length from the response
                reply = sock.recv(1024)
                reply = reply[2:]

                sock.close()

        except Exception as e:
            log.warning("Could not proxy request: {}".format(e), extra=clientip)
            dnslog.info("Could not proxy request: {}".format(e), extra=clientip)
        else:
            return reply

    def hstsbypass(self, real_domain, fake_domain, nameservers, d):
        clientip = {'clientip': self.client_address[0]}

        log.info("Resolving '{}' to '{}' for HSTS bypass".format(fake_domain, real_domain), extra=clientip)
        dnslog.info("Resolving '{}' to '{}' for HSTS bypass".format(fake_domain, real_domain), extra=clientip)

        response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1, aa=1, ra=1), q=d.q)

        nameserver_tuple = random.choice(nameservers).split('#')
        
        #First proxy the request with the real domain
        q = DNSRecord.question(real_domain).pack()
        r = self.proxyrequest(q, *nameserver_tuple)
        if r is None: return None

        #Parse the answer
        dns_rr = DNSRecord.parse(r).rr

        #Create the DNS response
        for res in dns_rr:
            if res.get_rname() == real_domain:
                res.set_rname(fake_domain)
                response.add_answer(res)
            else:
                response.add_answer(res)

        return response.pack()

# UDP DNS Handler for incoming requests
class UDPHandler(DNSHandler, SocketServer.BaseRequestHandler):

    def handle(self):
        (data,socket) = self.request
        response = self.parse(data)
        
        if response:
            socket.sendto(response, self.client_address)

# TCP DNS Handler for incoming requests            
class TCPHandler(DNSHandler, SocketServer.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)
        
        # Remove the addition "length" parameter used in the
        # TCP DNS protocol
        data = data[2:]
        response = self.parse(data)
        
        if response:
            # Calculate and add the additional "length" parameter
            # used in TCP DNS protocol 
            length = binascii.unhexlify("%04x" % len(response))            
            self.request.sendall(length+response)            

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):

    # Override SocketServer.UDPServer to add extra parameters
    def __init__(self, server_address, RequestHandlerClass):
        self.address_family = socket.AF_INET6 if DNSChef().ipv6 else socket.AF_INET

        SocketServer.UDPServer.__init__(self,server_address,RequestHandlerClass) 

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    
    # Override default value
    allow_reuse_address = True

    # Override SocketServer.TCPServer to add extra parameters
    def __init__(self, server_address, RequestHandlerClass):
        self.address_family = socket.AF_INET6 if DNSChef().ipv6 else socket.AF_INET

        SocketServer.TCPServer.__init__(self,server_address,RequestHandlerClass) 

class DNSChef(ConfigWatcher):

    version        = "0.4"
    tcp            = False
    ipv6           = False
    hsts           = False
    real_records   = {}
    nametodns      = {}
    server_address = "0.0.0.0"
    nameservers    = ["8.8.8.8"]
    port           = 53

    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def on_config_change(self):
        config = self.config['MITMf']['DNS']
        
        self.port = int(config['port'])

        # Main storage of domain filters
        # NOTE: RDMAP is a dictionary map of qtype strings to handling classe
        for qtype in RDMAP.keys():
            self.nametodns[qtype] = dict()

        # Adjust defaults for IPv6
        if config['ipv6'].lower() == 'on':
            self.ipv6 = True
            if config['nameservers'] == "8.8.8.8":
                self.nameservers = "2001:4860:4860::8888"

       # Use alternative DNS servers
        if config['nameservers']:
            self.nameservers = []

            if type(config['nameservers']) is str:
                self.nameservers.append(config['nameservers'])
            elif type(config['nameservers']) is list:
                self.nameservers = config['nameservers']

        for section in config.sections:

            if section in self.nametodns:
                for domain,record in config[section].iteritems():

                    # Make domain case insensitive
                    domain = domain.lower()

                    self.nametodns[section][domain] = record

        for k,v in self.config["SSLstrip+"].iteritems():
            self.real_records[v] = k

    def setHstsBypass(self):
        self.hsts = True

    def start(self):
        self.on_config_change()
        self.start_config_watch()

        try:
            if self.config['MITMf']['DNS']['tcp'].lower() == 'on':
                self.startTCP()
            else:
                self.startUDP()
        except socket.error as e:
            if "Address already in use" in e:
                shutdown("\n[DNS] Unable to start DNS server on port {}: port already in use".format(self.config['MITMf']['DNS']['port']))

    # Initialize and start the DNS Server        
    def startUDP(self):
        server = ThreadedUDPServer((self.server_address, int(self.port)), UDPHandler)
        # Start a thread with the server -- that thread will then start
        # more threads for each request
        server_thread = threading.Thread(target=server.serve_forever)

        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()

    # Initialize and start the DNS Server
    def startTCP(self):
        server = ThreadedTCPServer((self.server_address, int(self.port)), TCPHandler)

        # Start a thread with the server -- that thread will then start
        # more threads for each request
        server_thread = threading.Thread(target=server.serve_forever)

        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
