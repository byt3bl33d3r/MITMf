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

"""
 Originally coded by @xtr4nge
"""

#import multiprocessing
import threading
import logging
import json
import sys

from flask import Flask
from core.configwatcher import ConfigWatcher
from core.proxyplugins import ProxyPlugins

app = Flask(__name__)

class mitmfapi(ConfigWatcher):

    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state
        self.host = self.config['MITMf']['MITMf-API']['host']
        self.port = int(self.config['MITMf']['MITMf-API']['port'])

    @app.route("/")
    def getPlugins():
        # example: http://127.0.0.1:9999/
        pdict = {}
        
        #print ProxyPlugins().plugin_list
        for activated_plugin in ProxyPlugins().plugin_list:
            pdict[activated_plugin.name] = True

        #print ProxyPlugins().all_plugins
        for plugin in ProxyPlugins().all_plugins:
            if plugin.name not in pdict:
                pdict[plugin.name]  = False

        #print ProxyPlugins().pmthds
        
        return json.dumps(pdict)

    @app.route("/<plugin>")
    def getPluginStatus(plugin):
        # example: http://127.0.0.1:9090/cachekill
        for p in ProxyPlugins().plugin_list:
            if plugin == p.name:
                return json.dumps("1")

        return json.dumps("0")

    @app.route("/<plugin>/<status>")
    def setPluginStatus(plugin, status):
        # example: http://127.0.0.1:9090/cachekill/1 # enabled
        # example: http://127.0.0.1:9090/cachekill/0 # disabled
        if status == "1":
            for p in ProxyPlugins().all_plugins:
                if (p.name == plugin) and (p not in ProxyPlugins().plugin_list):
                    ProxyPlugins().add_plugin(p)
                    return json.dumps({"plugin": plugin, "response": "success"})

        elif status == "0":
            for p in ProxyPlugins().plugin_list:
                if p.name == plugin:
                    ProxyPlugins().remove_plugin(p)
                    return json.dumps({"plugin": plugin, "response": "success"})

        return json.dumps({"plugin": plugin, "response": "failed"})

    def startFlask(self):
        app.run(debug=False, host=self.host, port=self.port)

    #def start(self):
    #    api_thread = multiprocessing.Process(name="mitmfapi", target=self.startFlask)
    #    api_thread.daemon = True
    #    api_thread.start()

    def start(self):
        api_thread = threading.Thread(name='mitmfapi', target=self.startFlask)
        api_thread.setDaemon(True)
        api_thread.start()
