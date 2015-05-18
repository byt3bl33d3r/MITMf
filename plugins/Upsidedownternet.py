#!/usr/bin/env python2.7

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

import logging
from cStringIO import StringIO
from plugins.plugin import Plugin
from PIL import Image, ImageFile

mitmf_logger = logging.getLogger("mitmf")

class Upsidedownternet(Plugin):
    name       = "Upsidedownternet"
    optname    = "upsidedownternet"
    desc       = 'Flips images 180 degrees'
    version    = "0.1"
    has_opts   = False

    def initialize(self, options):
        globals()['Image'] = Image
        globals()['ImageFile'] = ImageFile
        self.options = options

    def serverHeaders(self, response, request):
        '''Kill the image skipping that's in place for speed reasons'''
        if request.isImageRequest:
            request.isImageRequest = False
            request.isImage = True
            self.imageType = response.headers['content-type'].split('/')[1].upper()

    def serverResponse(self, response, request, data):
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
                mitmf_logger.info("{} [Upsidedownternet] Flipped image".format(response.getClientIP()))
            except Exception as e:
                mitmf_logger.info("{} [Upsidedownternet] Error: {}".format(response.getClientIP(), e))
        
        return {'response': response, 'request': request, 'data': data}
