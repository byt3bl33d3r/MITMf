# Copyright (c) 2010-2011 Ben Schmidt
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
import inspect

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
    def setPlugins(self,plugins):
        '''Set the plugins in use'''
        self.plist = []
   
        #build a lookup list
        #need to clean up in future
        self.pmthds = {}
        for p in plugins:
            self.addPlugin(p)
    def addPlugin(self,p):
        '''Load a plugin'''
        self.plist.append(p)
        for mthd in p.implements:
            try:
                self.pmthds[mthd].append(getattr(p,mthd))
            except KeyError:
                self.pmthds[mthd] = [getattr(p,mthd)]
    def removePlugin(self,p):
        '''Unload a plugin'''
        self.plist.remove(p)
        for mthd in p.implements:
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
        args['request'] = args['self']
        del args['self']

        #calls any plugin that has this hook
        try:
            for f in self.pmthds[fname]:
                a = f(**args)
                if a != None: args = a
        except KeyError:
            pass

        #pass our changes to the locals back down
        return args

    def getInstance():
        if ProxyPlugins._instance == None:
            ProxyPlugins._instance = ProxyPlugins()

        return ProxyPlugins._instance

    getInstance = staticmethod(getInstance)
