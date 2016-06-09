# Copyright (c) 2014-2016 Marcello Salvati
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

from cStringIO import StringIO
from plugins.plugin import Plugin
from PIL import Image, ImageFile

class Upsidedownternet(Plugin):
    name       = "Upsidedownternet"
    optname    = "upsidedownternet"
    desc       = 'Flips images 180 degrees'
    version    = "0.1"

    def initialize(self, options):
        self.options = options

    def responseheaders(self, response, request):
        '''Kill the image skipping that's in place for speed reasons'''
        if request.isImageRequest:
            request.isImageRequest = False
            request.isImage = True
            self.imageType = response.responseHeaders.getRawHeaders('content-type')[0].split('/')[1].upper()

    def response(self, response, request, data):
        try:
            isImage = getattr(request, 'isImage')
        except AttributeError:
            isImage = False
        
        if isImage:
            try:
                #For some reason more images get parsed using the parser
                #rather than a file...PIL still needs some work I guess
                p = ImageFile.Parser()
                p.feed(data)
                im = p.close()
                im = im.transpose(Image.ROTATE_180)
                output = StringIO()
                im.save(output, format=self.imageType)
                data = output.getvalue()
                output.close()
                self.clientlog.info("Flipped image", extra=request.clientInfo)
            except Exception as e:
                self.clientlog.info("Error: {}".format(e), extra=request.clientInfo)
        
        return {'response': response, 'request': request, 'data': data}
