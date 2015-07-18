#! /usr/bin/env python2.7

# MSF-RPC - A  Python library to facilitate MSG-RPC communication with Metasploit

# Copyright (c) 2014-2016 Ryan Linn  - RLinn@trustwave.com, Marcello Salvati - byt3bl33d3r@gmail.com
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

import msgpack
import logging
import requests

from core.configwatcher import ConfigWatcher
from core.utils import shutdown

class Msfrpc:

    class MsfError(Exception):
        def __init__(self,msg):
            self.msg = msg
        def __str__(self):
            return repr(self.msg)

    class MsfAuthError(MsfError):
        def __init__(self,msg):
            self.msg = msg
    
    def __init__(self,opts=[]):
        self.host = opts.get('host') or "127.0.0.1"
        self.port = opts.get('port') or "55552"
        self.uri = opts.get('uri') or "/api/"
        self.ssl = opts.get('ssl') or False
        self.token = None
        self.headers = {"Content-type" : "binary/message-pack"}

    def encode(self, data):
        return msgpack.packb(data)

    def decode(self, data):
        return msgpack.unpackb(data)

    def call(self, method, opts=[]):
        if method != 'auth.login':
            if self.token == None:
                raise self.MsfAuthError("MsfRPC: Not Authenticated")

        if method != "auth.login":
            opts.insert(0, self.token)

        if self.ssl == True:
            url = "https://%s:%s%s" % (self.host, self.port, self.uri)
        else:
            url = "http://%s:%s%s" % (self.host, self.port, self.uri)
    

        opts.insert(0, method)
        payload = self.encode(opts)

        r = requests.post(url, data=payload, headers=self.headers)

        opts[:] = [] #Clear opts list
        
        return self.decode(r.content)

    def login(self, user, password):
        auth = self.call("auth.login", [user, password])
        try:
            if auth['result'] == 'success':
                self.token = auth['token']
                return True
        except:
            raise self.MsfAuthError("MsfRPC: Authentication failed")

class Msf(ConfigWatcher):
    '''
     This is just a wrapper around the Msfrpc class,
     prevents a lot of code re-use throught the framework

    '''
    def __init__(self):
        try:
            self.msf = Msfrpc({"host": self.config['MITMf']['Metasploit']['rpcip'], 
                               "port": self.config['MITMf']['Metasploit']['rpcport']})

            self.msf.login('msf', self.config['MITMf']['Metasploit']['rpcpass'])
        except Exception as e:
            shutdown("[Msfrpc] Error connecting to Metasploit: {}".format(e))

    @property
    def version(self):
        return self.msf.call('core.version')['version']

    def jobs(self):
        return self.msf.call('job.list')

    def jobinfo(self, pid):
        return self.msf.call('job.info', [pid])

    def killjob(self, pid):
        return self.msf.call('job.kill', [pid])

    def findjobs(self, name):
        jobs = self.jobs()
        pids = []
        for pid, jobname in jobs.iteritems():
            if name in jobname:
                pids.append(pid)

        return pids

    def sessions(self):
        return self.msf.call('session.list')

    def sessionsfrompeer(self, peer):
        sessions = self.sessions()
        for n, v in sessions.iteritems():
            if peer in v['tunnel_peer']:
                return n
        return None

    def sendcommand(self, cmd):
        #Create a virtual console
        console_id = self.msf.call('console.create')['id']

        #write the cmd to the newly created console
        self.msf.call('console.write', [console_id, cmd])

if __name__ == '__main__':
  
  # Create a new instance of the Msfrpc client with the default options
  client = Msfrpc({})

  # Login to the msfmsg server using the password "abc123"
  client.login('msf','abc123')

  # Get a list of the exploits from the server
  mod = client.call('module.exploits')
  
  # Grab the first item from the modules value of the returned dict
  print "Compatible payloads for : %s\n" % mod['modules'][0]
  
  # Get the list of compatible payloads for the first option
  ret = client.call('module.compatible_payloads',[mod['modules'][0]])
  for i in (ret.get('payloads')):
    print "\t%s" % i
