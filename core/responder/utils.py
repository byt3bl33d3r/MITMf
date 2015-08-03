#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import os
import sys
import re
import logging
import socket
import time
import settings
import sqlite3

def RespondToThisIP(ClientIp):

	if ClientIp.startswith('127.0.0.'):
		return False

	if len(settings.Config.RespondTo) and ClientIp not in settings.Config.RespondTo:
		return False

	if ClientIp in settings.Config.RespondTo or settings.Config.RespondTo == []:
		if ClientIp not in settings.Config.DontRespondTo:
			return True

	return False

def RespondToThisName(Name):

	if len(settings.Config.RespondToName) and Name.upper() not in settings.Config.RespondToName:
		return False

	if Name.upper() in settings.Config.RespondToName or settings.Config.RespondToName == []:
		if Name.upper() not in settings.Config.DontRespondToName:
			return True

	return False

def RespondToThisHost(ClientIp, Name):
	return (RespondToThisIP(ClientIp) and RespondToThisName(Name))

def IsOsX():
	return True if settings.Config.Os_version == "darwin" else False

def OsInterfaceIsSupported():
	if settings.Config.Interface != "Not set":
		return False if IsOsX() else True
	else:
		return False

def FindLocalIP(Iface):

	if Iface == 'ALL':
		return '0.0.0.0'

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.setsockopt(socket.SOL_SOCKET, 25, Iface+'\0')
		s.connect(("127.0.0.1",9))#RFC 863
		ret = s.getsockname()[0]
		s.close()

		return ret

	except socket.error:
		sys.exit(-1)

# Function used to write captured hashs to a file.
def WriteData(outfile, data, user):

	settings.Config.ResponderLogger.info("[*] Captured Hash: %s" % data)

	if os.path.isfile(outfile) == False:
		with open(outfile,"w") as outf:
			outf.write(data)
			outf.write("\n")
			outf.close()

	else:
		with open(outfile,"r") as filestr:
			if re.search(user.encode('hex'), filestr.read().encode('hex')):
				filestr.close()
				return False
			if re.search(re.escape("$"), user):
				filestr.close()
				return False

		with open(outfile,"a") as outf2:
			outf2.write(data)
			outf2.write("\n")
			outf2.close()

def SaveToDb(result):

	# Creating the DB if it doesn't exist
	if not os.path.exists(settings.Config.DatabaseFile):
		cursor = sqlite3.connect(settings.Config.DatabaseFile)
		cursor.execute('CREATE TABLE responder (timestamp varchar(32), module varchar(16), type varchar(16), client varchar(32), hostname varchar(32), user varchar(32), cleartext varchar(128), hash varchar(512), fullhash varchar(512))')
		cursor.commit()
		cursor.close()

	for k in [ 'module', 'type', 'client', 'hostname', 'user', 'cleartext', 'hash', 'fullhash' ]:
		if not k in result:
			result[k] = ''

	if len(result['user']) < 2:
		return

	if len(result['cleartext']):
		fname = '%s-%s-ClearText-%s.txt' % (result['module'], result['type'], result['client'])
	else:
		fname = '%s-%s-%s.txt' % (result['module'], result['type'], result['client'])
	
	timestamp = time.strftime("%d-%m-%Y %H:%M:%S")
	logfile = os.path.join('./logs/responder', fname)

	cursor = sqlite3.connect(settings.Config.DatabaseFile)
	res = cursor.execute("SELECT COUNT(*) AS count FROM responder WHERE module=? AND type=? AND LOWER(user)=LOWER(?)", (result['module'], result['type'], result['user']))
	(count,) = res.fetchone()

	if count == 0:
		
		# Write JtR-style hash string to file
		with open(logfile,"a") as outf:
			outf.write(result['fullhash'])
			outf.write("\n")
			outf.close()

		# Update database
		cursor.execute("INSERT INTO responder VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", (timestamp, result['module'], result['type'], result['client'], result['hostname'], result['user'], result['cleartext'], result['hash'], result['fullhash']))
		cursor.commit()

	cursor.close()

	# Print output
	if count == 0 or settings.Config.Verbose:

		if len(result['client']):
			settings.Config.ResponderLogger.info("[%s] %s Client   : %s" % (result['module'], result['type'], result['client']))
		if len(result['hostname']):
			settings.Config.ResponderLogger.info("[%s] %s Hostname : %s" % (result['module'], result['type'], result['hostname']))
		if len(result['user']):
			settings.Config.ResponderLogger.info("[%s] %s Username : %s" % (result['module'], result['type'], result['user']))

		# By order of priority, print cleartext, fullhash, or hash
		if len(result['cleartext']):
			settings.Config.ResponderLogger.info("[%s] %s Password : %s" % (result['module'], result['type'], result['cleartext']))
		elif len(result['fullhash']):
			settings.Config.ResponderLogger.info("[%s] %s Hash     : %s" % (result['module'], result['type'], result['fullhash']))
		elif len(result['hash']):
			settings.Config.ResponderLogger.info("[%s] %s Hash     : %s" % (result['module'], result['type'], result['hash']))

	else:
		settings.Config.PoisonersLogger.warning('Skipping previously captured hash for %s' % result['user'])

def Parse_IPV6_Addr(data):

	if data[len(data)-4:len(data)][1] =="\x1c":
		return False

	elif data[len(data)-4:len(data)] == "\x00\x01\x00\x01":
		return True

	elif data[len(data)-4:len(data)] == "\x00\xff\x00\x01":
		return True

	else:
		return False

def Decode_Name(nbname):
	#From http://code.google.com/p/dpkt/ with author's permission.
	try:
		from string import printable

		if len(nbname) != 32:
			return nbname
		
		l = []
		for i in range(0, 32, 2):
			l.append(chr(((ord(nbname[i]) - 0x41) << 4) | ((ord(nbname[i+1]) - 0x41) & 0xf)))
		
		return filter(lambda x: x in printable, ''.join(l).split('\x00', 1)[0].replace(' ', ''))
	
	except:
		return "Illegal NetBIOS name"

def NBT_NS_Role(data):
	Role = {
		"\x41\x41\x00":"Workstation/Redirector",
		"\x42\x4c\x00":"Domain Master Browser",
		"\x42\x4d\x00":"Domain Controller",
		"\x42\x4e\x00":"Local Master Browser",
		"\x42\x4f\x00":"Browser Election",
		"\x43\x41\x00":"File Server",
		"\x41\x42\x00":"Browser",
	}

	return Role[data] if data in Role else "Service not known"

# Useful for debugging
def hexdump(src, l=0x16):
	res = []
	sep = '.'
	src = str(src)

	for i in range(0, len(src), l):
		s = src[i:i+l]
		hexa = ''

		for h in range(0,len(s)):
			if h == l/2:
				hexa += ' '
			h = s[h]
			if not isinstance(h, int):
				h = ord(h)
			h = hex(h).replace('0x','')
			if len(h) == 1:
				h = '0'+h
			hexa += h + ' '

		hexa = hexa.strip(' ')
		text = ''

		for c in s:
			if not isinstance(c, int):
				c = ord(c)

			if 0x20 <= c < 0x7F:
				text += chr(c)
			else:
				text += sep

		res.append(('%08X:  %-'+str(l*(2+1)+1)+'s  |%s|') % (i, hexa, text))

	return '\n'.join(res)
