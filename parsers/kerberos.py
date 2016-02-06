import struct
from parsers.parser import Parser

class Kerberos(Parser):
    name = 'Kerberos'

    def TCP_Parser(self, payload, src_ip_port, dst_ip_port):
        kerb = str(pkt)[14:]
        d={}

        d['header_len']=ord(kerb[0]) & 0x0f
        d['data']=kerb[4*d['header_len']:]
        Data = d['data'][20:]

        '''
        Taken from Pcredz because I didn't want to spend the time doing this myself
        I should probably figure this out on my own but hey, time isn't free, why reinvent the wheel?
        Maybe replace this eventually with the kerberos python lib
        Parses Kerberosv5 hashes from packets
        '''
        try:
            MsgType = Data[21:22]
            EncType = Data[43:44]
            MessageType = Data[32:33]
        except IndexError:
            return

        if MsgType == "\x0a" and EncType == "\x17" and MessageType =="\x02":
            if Data[49:53] == "\xa2\x36\x04\x34" or Data[49:53] == "\xa2\x35\x04\x33":
                HashLen = struct.unpack('<b',Data[50:51])[0]
                if HashLen == 54:
                    Hash = Data[53:105]
                    SwitchHash = Hash[16:]+Hash[0:16]
                    NameLen = struct.unpack('<b',Data[153:154])[0]
                    Name = Data[154:154+NameLen]
                    DomainLen = struct.unpack('<b',Data[154+NameLen+3:154+NameLen+4])[0]
                    Domain = Data[154+NameLen+4:154+NameLen+4+DomainLen]
                    BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                    self.logger('MS Kerberos: {}'.format(BuildHash))

            if Data[44:48] == "\xa2\x36\x04\x34" or Data[44:48] == "\xa2\x35\x04\x33":
                HashLen = struct.unpack('<b',Data[47:48])[0]
                Hash = Data[48:48+HashLen]
                SwitchHash = Hash[16:]+Hash[0:16]
                NameLen = struct.unpack('<b',Data[HashLen+96:HashLen+96+1])[0]
                Name = Data[HashLen+97:HashLen+97+NameLen]
                DomainLen = struct.unpack('<b',Data[HashLen+97+NameLen+3:HashLen+97+NameLen+4])[0]
                Domain = Data[HashLen+97+NameLen+4:HashLen+97+NameLen+4+DomainLen]
                BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                self.logger('MS Kerberos: {}'.format(BuildHash))

            else:
                Hash = Data[48:100]
                SwitchHash = Hash[16:]+Hash[0:16]
                NameLen = struct.unpack('<b',Data[148:149])[0]
                Name = Data[149:149+NameLen]
                DomainLen = struct.unpack('<b',Data[149+NameLen+3:149+NameLen+4])[0]
                Domain = Data[149+NameLen+4:149+NameLen+4+DomainLen]
                BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                self.logger('MS Kerberos: {}'.format(BuildHash))


    def UDP_Parser(self, pkt, src_ip_port, dst_ip_port):
        kerb = str(pkt)[14:]
        d={}

        d['header_len']=ord(kerb[0]) & 0x0f
        d['data']=kerb[4*d['header_len']:]
        Data = d['data'][8:]

        '''
        Taken from Pcredz because I didn't want to spend the time doing this myself
        I should probably figure this out on my own but hey, time isn't free why reinvent the wheel?
        Maybe replace this eventually with the kerberos python lib
        Parses Kerberosv5 hashes from UDP packets
        '''

        try:
            MsgType = Data[17:18]
            EncType = Data[39:40]
        except IndexError:
            return

        if MsgType == "\x0a" and EncType == "\x17":
            try:
                if Data[40:44] == "\xa2\x36\x04\x34" or Data[40:44] == "\xa2\x35\x04\x33":
                    HashLen = struct.unpack('<b',Data[41:42])[0]
                    if HashLen == 54:
                        Hash = Data[44:96]
                        SwitchHash = Hash[16:]+Hash[0:16]
                        NameLen = struct.unpack('<b',Data[144:145])[0]
                        Name = Data[145:145+NameLen]
                        DomainLen = struct.unpack('<b',Data[145+NameLen+3:145+NameLen+4])[0]
                        Domain = Data[145+NameLen+4:145+NameLen+4+DomainLen]
                        BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                        self.logger('MS Kerberos: {}'.format(BuildHash))

                    if HashLen == 53:
                        Hash = Data[44:95]
                        SwitchHash = Hash[16:]+Hash[0:16]
                        NameLen = struct.unpack('<b',Data[143:144])[0]
                        Name = Data[144:144+NameLen]
                        DomainLen = struct.unpack('<b',Data[144+NameLen+3:144+NameLen+4])[0]
                        Domain = Data[144+NameLen+4:144+NameLen+4+DomainLen]
                        BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                        self.logger('MS Kerberos: {}'.format(BuildHash))

                else:
                    HashLen = struct.unpack('<b',Data[48:49])[0]
                    Hash = Data[49:49+HashLen]
                    SwitchHash = Hash[16:]+Hash[0:16]
                    NameLen = struct.unpack('<b',Data[HashLen+97:HashLen+97+1])[0]
                    Name = Data[HashLen+98:HashLen+98+NameLen]
                    DomainLen = struct.unpack('<b',Data[HashLen+98+NameLen+3:HashLen+98+NameLen+4])[0]
                    Domain = Data[HashLen+98+NameLen+4:HashLen+98+NameLen+4+DomainLen]
                    BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                    self.logger('MS Kerberos: {}'.format(BuildHash))
            except struct.error:
                return