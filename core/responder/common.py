#common functions that are used throughout the Responder's code

import os
import re

#Function used to write captured hashs to a file.
def WriteData(outfile, data, user):
	if os.path.isfile(outfile) == False:
		with open(outfile,"w") as outf:
			outf.write(data)
			outf.write("\n")
			outf.close()
	if os.path.isfile(outfile) == True:
		with open(outfile,"r") as filestr:
			if re.search(user.encode('hex'), filestr.read().encode('hex')):
				filestr.close()
				return False
			if re.search(re.escape("$"), user):
				filestr.close()
				return False
			else:
				with open(outfile,"a") as outf2:
					outf2.write(data)
					outf2.write("\n")
					outf2.close()

def Parse_IPV6_Addr(data):
	if data[len(data)-4:len(data)][1] =="\x1c":
		return False
	if data[len(data)-4:len(data)] == "\x00\x01\x00\x01":
		return True
	if data[len(data)-4:len(data)] == "\x00\xff\x00\x01":
		return True
	else:
		return False

#Function name self-explanatory
def Is_Finger_On(Finger_On_Off):
	if Finger_On_Off == True:
		return True
	if Finger_On_Off == False:
		return False

def RespondToSpecificHost(RespondTo):
	if len(RespondTo)>=1 and RespondTo != ['']:
		return True
	else:
		return False

def RespondToSpecificName(RespondToName):
	if len(RespondToName)>=1 and RespondToName != ['']:
		return True
	else:
		return False

def RespondToIPScope(RespondTo, ClientIp):
	if ClientIp in RespondTo:
		return True
	else:
		return False

def RespondToNameScope(RespondToName, Name):
	if Name in RespondToName:
		return True
	else:
		return False

##Dont Respond to these hosts/names.
def DontRespondToSpecificHost(DontRespondTo):
	if len(DontRespondTo)>=1 and DontRespondTo != ['']:
		return True
	else:
		return False

def DontRespondToSpecificName(DontRespondToName):
	if len(DontRespondToName)>=1 and DontRespondToName != ['']:
		return True
	else:
		return False

def DontRespondToIPScope(DontRespondTo, ClientIp):
	if ClientIp in DontRespondTo:
		return True
	else:
		return False

def DontRespondToNameScope(DontRespondToName, Name):
	if Name in DontRespondToName:
		return True
	else:
		return False

def IsOnTheSameSubnet(ip, net):
	net = net+'/24'
	ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
	netstr, bits = net.split('/')
	netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
	mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
	return (ipaddr & mask) == (netaddr & mask)

def FindLocalIP(Iface):
	return OURIP