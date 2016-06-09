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

import random
import os
from plugins.plugin import Plugin

class ImageRandomizer(Plugin):
    name       = "ImageRandomizer"
    optname    = "imgrand"
    desc       = 'Replaces images with a random one from a specified directory'
    version    = "0.1"

    def initialize(self, options):
        self.options = options
        self.img_dir = options.img_dir

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
                img = random.choice(os.listdir(self.options.img_dir))
                with open(os.path.join(self.options.img_dir, img), 'rb') as img_file:
                    data = img_file.read()
                    self.clientlog.info("Replaced image with {}".format(img), extra=request.clientInfo)
                    return {'response': response, 'request': request, 'data': data}
            except Exception as e:
                self.clientlog.info("Error: {}".format(e), extra=request.clientInfo)

    def options(self, options):
        options.add_argument("--img-dir", type=str, metavar="DIRECTORY", help="Directory with images")