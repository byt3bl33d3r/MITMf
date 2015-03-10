import logging
from cStringIO import StringIO
from plugins.plugin import Plugin
from PIL import Image


class Upsidedownternet(Plugin):
    name       = "Upsidedownternet"
    optname    = "upsidedownternet"
    desc       = 'Flips images 180 degrees'
    implements = ["handleResponse", "handleHeader"]
    version    = "0.1"
    has_opts   = False
    req_root   = False

    def initialize(self, options):
        from PIL import Image, ImageFile
        globals()['Image'] = Image
        globals()['ImageFile'] = ImageFile
        self.options = options

    def handleHeader(self, request, key, value):
        '''Kill the image skipping that's in place for speed reasons'''
        if request.isImageRequest:
            request.isImageRequest = False
            request.isImage = True
            request.imageType = value.split("/")[1].upper()

    def handleResponse(self, request, data):
        try:
            isImage = getattr(request, 'isImage')
        except AttributeError:
            isImage = False
        
        if isImage:
            try:
                image_type = request.imageType
                #For some reason more images get parsed using the parser
                #rather than a file...PIL still needs some work I guess
                p = ImageFile.Parser()
                p.feed(data)
                im = p.close()
                im = im.transpose(Image.ROTATE_180)
                output = StringIO()
                im.save(output, format=image_type)
                data = output.getvalue()
                output.close()
                logging.info("%s Flipped image" % request.client.getClientIP())
            except Exception as e:
                logging.info("%s Error: %s" % (request.client.getClientIP(), e))
        return {'request': request, 'data': data}
