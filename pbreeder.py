#!/usr/bin/env python3

import socket
from struct import pack
from random import randint
from binascii import hexlify
from binascii import unhexlify
from threading import Thread
from time import time
from math import modf

# All TPID
TPID_IP4 = b'\x08\x00'			# IP4
TPID_IP6 = b'\x86\xdd'			# IP6
TPID_ARP = b'\x08\x06'          # ARP
TPID_8021Q = b'\x81\x00'        # 802.1q VLAN
TPID_AARP = b'\x08\x42'         # Apple ARP
TPID_AT = b'\x80\x9b'           # AppleTalk
TPID_RARP = b'\x80\x35'         # Reverse ARP
TPID_8021AE = b'\x88\xe5'       # 802.1ae MACsec
TPID_8021X = b'\x88\x8e'        # 802.1x EAP on LAN
TPID_LLDP = b'\x88\xcc'         # Link Layer Discovery Protocol


# Sniff class to create a sniffing object
class Sniff(object):
    # Initialization of the sniffing : device required
    def __init__(self, dev, tpid):
        self.packet = None
        self.dev = dev
        # Select a physical protocol
        self.int_tpid = socket.htons(tpid)
        self.frame = None

    # Hidden part of the start function, permit to be launched in a thread.
    # Ths START function need to be launched by the user.
    def _hidden_start(self):
        self.packet = ""
        # Global pcap header (hex)
        self.pcap_file = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00' + \
                         b'\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00' + \
                         b'\x01\x00\x00\x00'
        self.raw = b''
        # Define the raw socket.
        self.sniffer = socket.socket(socket.PF_PACKET,
                                     socket.SOCK_RAW,
                                     self.int_tpid)
        # Bind the raw socket on the interface.
        self.sniffer.bind((self.dev, 0))
        while True:
            # Wait for 2048 bits on the binded socket
            self.frame = self.sniffer.recv(2048)
            if self.frame is None:
                continue
            self.raw += self.frame
            # Format the received message
            self.pcap_formatting()
            # Unpacking all bits and put it in good values of the class.
            self.src = hexlify(self.frame)[0:12]
            self.dst = hexlify(self.frame)[12:24]
            self.datas = hexlify(self.frame[24:(len(self.frame)-1)])
            # Format the received message to be human readable.
            self.normal_formatting()

    # Format the packet in pcap file format
    def pcap_formatting(self):
        # Take the date and transform it into the good format.
        ms, s = modf(time())
        epoch_s = int(s)
        epoch_ms = int(ms * 1000000)
        # Header built for each packet received
        self.pcap_file += pack('@iiii',
                               epoch_s,
                               epoch_ms,
                               len(self.frame),
                               len(self.frame)) + self.frame

    # Format to become human readable
    def normal_formatting(self):
        self.packet += "\nSrc: "+self.src.decode('utf-8')+"\nDst: " + \
                       self.dst.decode('utf-8')+"\nDatas: " + \
                       self.datas.decode('utf-8')+"\n"

    # Start function to launch the sniffer.
    def start(self):
        # A Thread is created as a daemon process.
        self.process = Thread(target=self._hidden_start, args=())
        self.process.daemon = True
        self.process.start()
        return 0

    # Stop function to close the sniffer.
    def stop(self):
        self.sniffer.close()
        return 0

    # Show function to permit user to see human readable packets.
    def show(self):
        print(self.packet)
        return 0

    # Write the pcap file.
    def pcap(self, path):
        f = open(path, 'w+b')
        f.write(self.pcap_file)
        f.close()


# Checksum class for calculation
class Checksum():
    # TCP checksum calculating
    def calc(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + (msg[i+1])
            s += w
        s = (s >> 16) + (s & 0xffff)
        # s = s + (s >> 16);
        # complement and mask to 4 byte short
        s = ~s & 0xffff
        return s


# ARP PACKET settings, configuration and sending.
class ARP(object):
    # ARP packet initialization
    def __init__(self, src_mac, dst_mac, source_ip, dest_ip, iface):
        # Hardware type
        self.htype = '1'
        # Protocol type
        self.ptype = '\x08\x06'
        # Hardware length
        self.hlen = '6'
        # Protocol length
        self.plen = '4'
        # Operation (1=request, 2=reply)
        self.op = '1'
        # Sender MAC address
        self.source_mac = unhexlify(src_mac.replace(":", ""))
        # Receiver MAC address
        self.dest_mac = unhexlify(dst_mac.replace(":", ""))
        # Sender IP address
        self.source_ip = source_ip
        # Receiver IP address
        self.dest_ip = dest_ip
        # Interface to use with ARP
        self.iface = iface

    # Frame compilation
    def make(self):
        # Sources and destination
        eth = pack(">6s6s",
                   self.source_mac,
                   self.dest_mac) + TPID_ARP
        # Arp request or replay contain
        arp = pack(">2s2s1s1s2s6s4s6s4s",
                   self.htype,
                   self.ptype,
                   self.hlen,
                   self.plen,
                   self.op,
                   self.source_mac,
                   self.source_ip,
                   self.dest_mac,
                   self.dest_ip)
        # Padding to valid the frame
        pad = b'\x00' * 12
        # Final transformation
        self.frame = eth + arp + pad
        return hexlify(self.frame)

    # Send the ARP packet.
    def send(self):
        # With a raw socket.
        mysock = socket.socket(socket.PF_PACKET,
                               socket.SOCK_RAW,
                               socket.htons(0x0806))
        mysock.sendto(self.frame, (self.iface, 0))


# IP PACKET settings, configuration and sending.
class IP(object):
    # IP header first settings
    def __init__(self, dst_mac, src_mac, src_ip, dst_ip, proto, iface):
        self.source_mac = unhexlify(src_mac.replace(":", ""))
        self.dest_mac = unhexlify(dst_mac.replace(":", ""))
        # Physical interface
        self.iface = iface
        # IP version
        self.ip_ver = 4
        # IP header Length
        self.ip_ihl = 5
        # IP type of Service
        self.ip_tos = 0
        # IP total length (kernel will auto-fill total length)
        self.ip_tot_len = 0
        # IP id of the packet (identification if fragmented)
        self.ip_id = randint(0, 65535)
        # IP fragment offset (number of the fragment)
        self.ip_frag_off = 0
        # IP TTL
        self.ip_ttl = 255
        # IP source address
        self.ip_source = socket.inet_aton(src_ip)
        self.src_ip = src_ip
        # IP destination address
        self.ip_dest = socket.inet_aton(dst_ip)
        self.dst_ip = dst_ip
        # IP protocol selection: TCP=6, UDP=17, ICMP=1
        if proto == "TCP" or proto == "tcp":
            self.ip_proto = 6
            # We call the TCP class to create a new object.
            self.MODE = TCP(self.ip_source, self.ip_dest,
                            self.ip_proto)
        elif proto == "UDP" or proto == "udp":
            self.ip_proto = 17
            pseudo_header = pack('>4s4s', self.ip_source,
                                 self.ip_dest)
            # UDP class
            self.MODE = UDP(pseudo_header)
        elif proto == "ICMP" or proto == "icmp":
            self.ip_proto = 1
            # ICMP class
            self.MODE = ICMP()
        # IP checksum to detect error (kernel will auto-fill error checksum)
        self.ip_check = 0

    # Function to show the packet in a table.
    def show(self):
        horiz_bar = \
            "¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤"
        self.string_to_show = """
        {}
        \tSource hw address:\t{}\t\t\t\t
        {}
        \tDestination hw address:\t{}\t\t\t
        {}
        \t\t\tIPv{}\t\t\t\t|\t\t\tIHL:\t{}\t\t\t
        {}
        \t\t\tToS:\t{}\t\t\t|\t\t\tLength:\t{}\t\t\t
        {}
        \t\tID:\t{}\t|\tFlags\t|\t\tFragment Offset:\t{}\t
        {}
        \tTTL:\t{}\t\t|\t\tProto:\t{}\t|\t\tChecksum:{}\t\t
        {}
        \t\t\tSource address:\t\t{}\t\t\t\t\t\t
        {}
        \t\t\tDestination address:\t{}\t\t\t\t
        {}
        <\t\t\t\t\t{}\t\t\t\t\t>
        \tSrc:\t{}\t|\tDst:\t{}\t|\t\tChecksum:\t{}\t\t
        {}
        """.format(
            horiz_bar,
            self.source_mac,
            horiz_bar,
            self.dest_mac,
            horiz_bar,
            self.ip_ver,
            self.ip_ihl,
            horiz_bar,
            self.ip_tos,
            self.ip_tot_len,
            horiz_bar,
            self.ip_id,
            self.ip_frag_off,
            horiz_bar,
            self.ip_ttl,
            self.ip_proto,
            self.ip_check,
            horiz_bar,
            self.src_ip,
            horiz_bar,
            self.dst_ip,
            horiz_bar,
            self.MODE.name,
            self.MODE.src,
            self.MODE.dst,
            self.MODE.checking,
            horiz_bar,
        )
        print(self.string_to_show)

    # IP header compilation (which call the compilation for mode which have
    # been choose by the user earlier)
    def make(self):
        eth = pack(">6s6s",
                   self.source_mac,
                   self.dest_mac) + TPID_IP4
        self.ip_ver_ihl = (self.ip_ver << 4) + self.ip_ihl
        # Protocol packet compilation
        self.MODE.make()
        # 1st packing
        self.ip_header = pack('>BBHHHBBH4s4s',
                              self.ip_ver_ihl,
                              self.ip_tos,
                              self.ip_tot_len,
                              self.ip_id,
                              self.ip_frag_off,
                              self.ip_ttl,
                              self.ip_proto,
                              self.ip_check,
                              self.ip_source,
                              self.ip_dest)
        # Lenght calculation
        self.ip_tot_len = len(self.ip_header) + self.MODE.length
        # 2nd packing
        self.ip_header = pack('>BBHHHBBH4s4s',
                              self.ip_ver_ihl,
                              self.ip_tos,
                              self.ip_tot_len,
                              self.ip_id,
                              self.ip_frag_off,
                              self.ip_ttl,
                              self.ip_proto,
                              self.ip_check,
                              self.ip_source,
                              self.ip_dest)
        # Checksum calculation
        self.ip_check = Checksum().calc(self.ip_header)
        # 3rd & last packing
        self.ip_header = pack('>BBHHHBBH4s4s',
                              self.ip_ver_ihl,
                              self.ip_tos,
                              self.ip_tot_len,
                              self.ip_id,
                              self.ip_frag_off,
                              self.ip_ttl,
                              self.ip_proto,
                              self.ip_check,
                              self.ip_source,
                              self.ip_dest)
        self.packet = bytes(eth + self.ip_header + self.MODE.mode_header)
        return hexlify(self.packet)

    # Packet sending (must be done after compilation of the IP class
    # and the MODE class)
    def send(self):
        mysock = socket.socket(socket.AF_PACKET,
                               socket.SOCK_RAW,
                               socket.IPPROTO_RAW)
        mysock.sendto(self.packet, (self.iface, 0))


# TRANSFER CONTROL PROTOCOL
class TCP():
    # TCP header first settings
    def __init__(self, ip_source, ip_dest, proto):
        self.ip_source = ip_source
        self.ip_dest = ip_dest
        self.protocol = proto
        self.name = "Transfer Control Protocol"
        # TCP source port
        self.src = randint(1025, 65535)
        # TCP dest port
        self.dst = 80
        # TCP sequence number (SYN)
        self.seq = 0
        # TCP acknowledge number (ACK)
        self.ack_seq = 0
        # TCP header size (self.tcp header, 5 * 4 = 20)
        self.offset = 5
        # TCP FLAGS
        # - No more data from sender
        self.fl_fin = 0
        # - Synchronized sequence number
        self.fl_syn = 0
        # - Resets the connection
        self.fl_rst = 0
        # - Asks to push the buffered data to the receiving application
        self.fl_psh = 0
        # - After the initial SYN packet sent, must set this flag
        self.fl_ack = 0
        # - indicates that the Urgent pointer
        self.fl_urg = 0
        # Specifies the number of TCP window size units
        self.window = socket.htons(65535)
        # TCP errror checking of header and data
        self.checking = 0
        # If self.tcp_urg is set, last urgent data byte
        self.urg_ptr = 0
        # TCP datas
        self.datas = b''

    # TCP header compilation
    def make(self):
        # offset_res = (self.offset << 4) + 0
        offset_res = 0
        # Fusion of all TCP flags
        tcp_flags = self.fl_fin + \
                    (self.fl_syn << 1) + \
                    (self.fl_rst << 2) + \
                    (self.fl_psh << 3) + \
                    (self.fl_ack << 4) + \
                    (self.fl_urg << 5)
        # First TCP header making
        self.mode_header = pack('>HHLLBBHHH',
                                self.src,
                                self.dst,
                                self.seq,
                                self.ack_seq, offset_res,
                                tcp_flags,
                                self.window,
                                0,
                                self.urg_ptr)
        offset_res = (self.offset << 4) + len(self.mode_header)
        # Second TCP header making (for checksum)
        self.mode_header = pack('>HHLLBBHHH',
                                self.src,
                                self.dst,
                                self.seq,
                                self.ack_seq,
                                offset_res,
                                tcp_flags,
                                self.window,
                                0,
                                self.urg_ptr)
        self.p_h = pack('>4s4sBBH',
                        self.ip_source,
                        self.ip_dest,
                        0,
                        self.protocol,
                        len(self.mode_header+self.datas))
        self.checking = Checksum().calc(self.p_h+self.mode_header+self.datas)
        # TCP header of the packet
        self.mode_header = pack('>HHLLBBHHH',
                                self.src,
                                self.dst,
                                self.seq,
                                self.ack_seq,
                                offset_res,
                                tcp_flags,
                                self.window,
                                self.checking,
                                self.urg_ptr)
        # Data include in the TCP packet
        # Final fusion of the bits
        self.mode_header = self.mode_header + self.datas.encode("utf-8")
        self.length = len(self.mode_header)
        return 0


# USER DATAGRAM PROTOCOL
class UDP():
    # UDP header first settings
    def __init__(self, pseudo_header):
        self.p_h = pseudo_header
        self.name = 'User Datagram protocol'
        # UDP source port
        self.src = randint(1025, 65535)
        # UDP dest port
        self.dst = 22
        # UDP checksum
        self.checking = 0
        # UDP data
        self.datas = b''
        # UDP header & UDP data size
        self.length = 0

    # UDP header compilation
    def make(self):
        self.mode_header = pack('>HHHH',
                                self.src,
                                self.dst,
                                self.length,
                                self.checking)
        self.length = len(self.mode_header) + len(self.datas)
        self.mode_header = pack('>HHHH',
                                self.src,
                                self.dst,
                                self.length,
                                self.checking)
        self.p_h = self.p_h + pack('>BBH', 0, 17, self.length)
        self.checking = Checksum().calc(self.p_h + self.mode_header)
        self.mode_header = pack('>HHHH',
                                self.src,
                                self.dst,
                                self.length,
                                self.checking) + self.datas


# INTERNET MESSAGE CONTROL PROTOCOL
class ICMP():
    # ICMP initialisation
    def __init__(self):
        self.name = "Internet Message Control Protocol"
        # Type of ICMP message
        # CODE FOR ICMP MESSAGES
        # TYPE   Description
        # ----   -----------
        # 0      Echo Reply
        # 3      Destination Unreachable
        # 4      Source Quench
        # 5      Redirect Message
        # 8      Echo Request (selected by default)
        self.type_icmp = 8
        # 11     Time Exceeded
        # 12     Parameter Problem
        # 13     Timestamp Request
        # 14     Timestamp Reply
        # 15     Information Request (No Longer Used)
        # 16     Information Reply (No Longer Used)
        # 17     Address Mask Request
        # 18     Address Mask Reply
        # Fake src and dst port to kill bugs
        self.src = "None"
        self.dst = "None"
        # Type 8, code 0 = ask an echo-request
        self.code = 0
        # Checksum
        self.checking = 0
        # ICMP ID packet
        self.ID = randint(0, 65535)
        # ICMP datas in packet
        self.datas = bytes(70 * 'PING', "ascii")

    # Packet compilation for ICMP packets
    def make(self):
        # First ICMP packet compilation
        self.mode_header = pack('>bbHH',
                                self.type_icmp,
                                self.code,
                                self.checking, self.ID) + self.datas
        # Checksum calculation
        self.checking = Checksum().calc(self.mode_header)
        # Finale ICMP packet compilation
        self.mode_header = pack('>bbHH',
                                self.type_icmp,
                                self.code,
                                self.checking,
                                self.ID) + self.datas
        self.length = len(self.mode_header)
        return 0
