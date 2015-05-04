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
from PIL import Image

class Upsidedownternet(Plugin):
    name       = "Upsidedownternet"
    optname    = "upsidedownternet"
    desc       = 'Flips images 180 degrees'
    implements = ["handleResponse", "handleHeader"]
    version    = "0.1"
    has_opts   = False

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
                mitmf_logger.info("{} Flipped image".format(request.client.getClientIP()))
            except Exception as e:
                mitmf_logger.info("{} Error: {}".format(request.client.getClientIP(), e))
        
        return {'request': request, 'data': data}
