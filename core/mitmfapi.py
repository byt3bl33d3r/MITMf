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
from core.sergioproxy.ProxyPlugins import ProxyPlugins

app = Flask(__name__)

class mitmfapi:

    _instance = None
    host = ConfigWatcher.getInstance().config['MITMf']['MITMf-API']['host']
    port = int(ConfigWatcher.getInstance().config['MITMf']['MITMf-API']['port'])

    @staticmethod
    def getInstance():
        if mitmfapi._instance is None:
            mitmfapi._instance = mitmfapi()

        return mitmfapi._instance

    @app.route("/")
    def getPlugins():
        # example: http://127.0.0.1:9090/
        pdict = {}
        
        #print ProxyPlugins.getInstance().plist
        for activated_plugin in ProxyPlugins.getInstance().plist:
            pdict[activated_plugin.name] = True

        #print ProxyPlugins.getInstance().plist_all
        for plugin in ProxyPlugins.getInstance().plist_all:
            if plugin.name not in pdict:
                pdict[plugin.name]  = False

        #print ProxyPlugins.getInstance().pmthds
        
        return json.dumps(pdict)

    @app.route("/<plugin>")
    def getPluginStatus(plugin):
        # example: http://127.0.0.1:9090/cachekill
        for p in ProxyPlugins.getInstance().plist:
            if plugin == p.name:
                return json.dumps("1")

        return json.dumps("0")

    @app.route("/<plugin>/<status>")
    def setPluginStatus(plugin, status):
        # example: http://127.0.0.1:9090/cachekill/1 # enabled
        # example: http://127.0.0.1:9090/cachekill/0 # disabled
        if status == "1":
            for p in ProxyPlugins.getInstance().plist_all:
                if (p.name == plugin) and (p not in ProxyPlugins.getInstance().plist):
                    ProxyPlugins.getInstance().addPlugin(p)
                    return json.dumps({"plugin": plugin, "response": "success"})

        elif status == "0":
            for p in ProxyPlugins.getInstance().plist:
                if p.name == plugin:
                    ProxyPlugins.getInstance().removePlugin(p)
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