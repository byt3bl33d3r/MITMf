from plugins.plugin import Plugin
import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *
from libs.responder.Responder import *

class Responder(Plugin):
    name = "Responder"
    optname = "responder"
    desc = ""
    has_opts = True

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.interface = options.interface
        self.ip_address = None

        if os.geteuid() != 0:
            sys.exit("[-] Responder plugin requires root privileges")

        try:
            self.ip_address = get_if_addr(options.interface)
            if self.ip_address == "0.0.0.0":
                sys.exit("[-] Interface %s does not have an IP address" % self.interface)
        except Exception, e:
            sys.exit("[-] Error retrieving interface IP address: %s" % e)

        start_responder(options, self.ip_address)

    def add_options(self, options):
        options.add_argument('--analyze', dest="Analyse", action="store_true", help="Allows you to see NBT-NS, BROWSER, LLMNR requests from which workstation to which workstation without poisoning")
        options.add_argument('--basic', dest="Basic", default=False, action="store_true", help="Set this if you want to return a Basic HTTP authentication. If not set, an NTLM authentication will be returned")
        options.add_argument('--wredir', dest="Wredirect", default=False, action="store_true", help="Set this to enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network (like classics 'nbns spoofer' would). Default value is therefore set to False")
        options.add_argument('--nbtns', dest="NBTNSDomain", default=False, action="store_true", help="Set this to enable answers for netbios domain suffix queries. Answering to domain suffixes will likely break stuff on the network (like a classic 'nbns spoofer' would). Default value is therefore set to False")
        options.add_argument('--fingerprint', dest="Finger", default=False, action="store_true", help = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query")
        options.add_argument('--wpad', dest="WPAD_On_Off", default=False, action="store_true", help = "Set this to start the WPAD rogue proxy server. Default value is False")
        options.add_argument('--forcewpadauth', dest="Force_WPAD_Auth", default=False, action="store_true", help = "Set this if you want to force NTLM/Basic authentication on wpad.dat file retrieval. This might cause a login prompt in some specific cases. Therefore, default value is False")
        options.add_argument('--lm', dest="LM_On_Off", default=False, action="store_true", help="Set this if you want to force LM hashing downgrade for Windows XP/2003 and earlier. Default value is False")
        options.add_argument('--verbose', dest="Verbose", action="store_true", help="More verbose")