import re
from netlib.http import decoded
from plugins.plugin import Plugin

class Replace(Plugin):
    name    = 'Replace'
    optname = 'replace'
    desc    = 'Replace arbitrary content in HTML content'
    version = '0.2'

    def response(self, context, flow):
        if flow.response.headers.get_first("content-type", "").startswith("text/html"):
            with decoded(flow.response):
                for rulename, regexs in self.config['Replace'].iteritems():
                    for regex1,regex2 in regexs.iteritems():
                        if re.search(regex1, flow.response.content):
                            data = re.sub(regex1, regex2, flow.response.content)
                            context.log("[Replace] Occurances matching '{}' replaced with '{}' according to rule '{}' on {}".format(regex1, regex2, rulename, flow.request.host))

                            flow.response.content = data
