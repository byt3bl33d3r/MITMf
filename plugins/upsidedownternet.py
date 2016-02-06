import cStringIO
from PIL import Image
from libmproxy.models import decoded
from plugins.plugin import Plugin

class Upsidedownternet(Plugin):
    name = 'Upsidedownternet'
    optname = 'upsidedownternet'
    desc = 'Flips images 180 degrees'
    version = '1.0'

    def response(self, context, flow):
        if flow.response.headers.get("content-type", "").startswith("image"):
            with decoded(flow.response):  # automatically decode gzipped responses.
                try:
                    s = cStringIO.StringIO(flow.response.content)
                    img = Image.open(s).rotate(180)
                    s2 = cStringIO.StringIO()
                    img.save(s2, "png")
                    flow.response.content = s2.getvalue()
                    flow.response.headers["content-type"] = "image/png"
                except:  # Unknown image types etc.
                    pass