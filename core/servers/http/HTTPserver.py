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
import threading
import sys

from core.utils import shutdown
from core.configwatcher import ConfigWatcher
from flask import Flask

class HTTPserver(ConfigWatcher):

    server = Flask("HTTPserver")
    func_list = []

    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def start_flask(self):

        @self.server.route('/', defaults={'path': '/'})
        @self.server.route('/<path:path>')
        def catch_all(path):
            for func in self.func_list:
                resp = func(path)
                if resp:
                    return resp
            return path

        self.server.run(debug=False, host='0.0.0.0', port=int(self.config['MITMf']['HTTP']['port']))

    def start(self):
        self.setup_http_logger()
        server_thread = threading.Thread(name='HTTPserver', target=self.start_flask)
        server_thread.setDaemon(True)
        server_thread.start()

    def add_endpoint(self, function):
        self.func_list.append(function)

    def setup_http_logger(self):
        formatter = logging.Formatter("%(asctime)s [HTTP] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        flask_logger = logging.getLogger('werkzeug')
        flask_logger.propagate = False
        fileHandler = logging.FileHandler("./logs/mitmf.log")
        fileHandler.setFormatter(formatter)
        flask_logger.addHandler(fileHandler)
