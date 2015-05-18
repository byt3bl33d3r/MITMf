# Copyright (c) 2010-2011 Ben Schmidt, Marcello Salvati
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

import sys
import logging
import inspect
import traceback

mitmf_logger = logging.getLogger("mitmf")

class ProxyPlugins:
    '''
    This class does some magic so that all we need to do in
    ServerConnection is do a self.plugins.hook() call
    and we will call any plugin that implements the function
    that it came from with the args passed to the original
    function.

    To do this, we are probably abusing the inspect module,
    and if it turns out to be too slow it can be changed. For
    now, it's nice because it makes for very little code needed
    to tie us in.

    Sadly, propagating changes back to the function is not quite
    as easy in all cases :-/ . Right now, changes to local function
    vars still have to be set back in the function. This only happens
    in handleResponse, but is still annoying.
    '''
    _instance = None
    
    plist = []
    mthdDict = {"connectionMade": "clientRequest", "handleResponse": "serverResponse", "handleHeader": "serverHeaders", "handleEndHeaders":"serverHeaders"}
    pmthds = {}

    @staticmethod
    def getInstance():
        if ProxyPlugins._instance == None:
            ProxyPlugins._instance = ProxyPlugins()

        return ProxyPlugins._instance

    def setPlugins(self, plugins):
        '''Set the plugins in use'''

        for p in plugins:
            self.addPlugin(p)

        mitmf_logger.debug("[ProxyPlugins] Loaded {} plugin/s".format(len(self.plist)))

    def addPlugin(self,p):
        '''Load a plugin'''
        self.plist.append(p)
        mitmf_logger.debug("[ProxyPlugins] Adding {} plugin".format(p.name))
        for mthd,pmthd in self.mthdDict.iteritems():
            try:
                self.pmthds[mthd].append(getattr(p,pmthd))
            except KeyError:
                self.pmthds[mthd] = [getattr(p,pmthd)]

    def removePlugin(self,p):
        '''Unload a plugin'''
        self.plist.remove(p)
        mitmf_logger.debug("[ProxyPlugins] Removing {} plugin".format(p.name))
        for mthd,pmthd in self.mthdDict.iteritems():
            self.pmthds[mthd].remove(p)

    def hook(self):
        '''Magic to hook various function calls in sslstrip'''
        #gets the function name and args of our caller
        frame = sys._getframe(1)
        fname = frame.f_code.co_name
        keys,_,_,values = inspect.getargvalues(frame)

        #assumes that no one calls del on an arg :-/
        args = {}
        for key in keys:
            args[key] = values[key]
    
        #prevent self conflict
        if (fname == "handleResponse") or (fname == "handleHeader") or (fname == "handleEndHeaders"):
            args['request']  = args['self']
            args['response'] = args['self'].client
        else:
            args['request'] = args['self']

        del args['self']

        mitmf_logger.debug("[ProxyPlugins] hooking {}()".format(fname))
        #calls any plugin that has this hook
        try:
            for f in self.pmthds[fname]:
                a = f(**args)
                if a != None: args = a
        except KeyError as e:
            pass
        except Exception as e:
            #This is needed because errors in hooked functions won't raise an Exception + Traceback (which can be infuriating)
            mitmf_logger.error("[ProxyPlugins] Exception occurred in hooked function")
            traceback.print_exc()

        #pass our changes to the locals back down
        return args
