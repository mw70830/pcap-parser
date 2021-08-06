#!/usr/bin/python3
# -*- coding: utf-8 -*-
import argparse
import os
import pyshark
from scapy.all import *

class TcpFlagInfo:
    #global variable define
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    @staticmethod
    def make_flag_str(self, f):
        ret = "."
        if (f == None):
            return 'None'
        if (f & self.FIN):
            ret = ret + '+FIN'
        if (f & self.SYN):
            ret = ret + '+SYN'
        if (f & self.RST):
            ret = ret + '+RST'
        if (f & self.PSH):
            ret = ret + '+PSH'
        if (f & self.ACK):
            ret = ret + '+ACK'
        if (f & self.URG):
            ret = ret + '+URG'
        if (f & self.ECE):
            ret = ret + '+ECE'
        if (f & self.CWR):
            ret = ret + '+CWR'
        return ret

    @staticmethod
    def flagnumber2char(self, f):
        ret = ''
        if (f == None):
            return 'None'
        chkf = f & ~self.FIN
        if (f & self.FIN):
            ret = ret + 'F'
        if (f & self.SYN):
            ret = ret + 'S'
        if (f & self.RST):
            ret = ret + 'R'
        if (f & self.PSH):
            ret = ret + 'P'
        if (f & self.ACK):
            ret = ret + 'A'
        if (f & self.URG):
            ret = ret + 'U'
        if (f & self.ECE):
            ret = ret + 'E'
        if (f & self.CWR):
            ret = ret + 'C'
        return ret

    @staticmethod
    def convert_tcp_flag(self, in_flag):
        if in_flag == "syn":
            return "S"
        elif in_flag == "fin":
            return "F"
        elif in_flag == "fin+ack":
            return "FA"
        elif in_flag == "rst":
            return "R"
        elif in_flag == "ack":
            return "A"
        elif in_flag == "push":
            return "P"
        elif in_flag == "push+ack":
            return "PA"
        elif in_flag == "urg":
            return "U"
        elif in_flag == "ece":
            return "E"
        elif in_flag == "cwr":
            return "C"
        elif in_flag == "syn+ack":
            return "SA"
        return "N/A"

    @staticmethod
    def convert_tcp_flag2num(self, in_flag):
        ret = 0x00

        if in_flag == "S":
            ret = self.SYN
        elif in_flag == "F":
            ret = self.FIN
        elif in_flag == "FA":
            ret = self.FIN + self.ACK
        elif in_flag == "R":
            ret = self.RST
        elif in_flag == "A":
            ret = self.ACK
        elif in_flag == "P":
            ret = self.PSH
        elif in_flag == "PA":
            ret = self.PSH + self.ACK
        elif in_flag == "U":
            ret = self.URG
        elif in_flag == "E":
            ret = self.ECE
        elif in_flag == "C":
            ret = self.CWR
        elif in_flag == "SA":
            ret = self.SYN + self.ACK

        return ret
   
class Session:
    def __init__(self, packet):
        # FIXED DATA
        self.start_time = packet.sniff_time
        self.stream_id = int(packet.tcp.stream, 0)

        #packet.eth
        self.src_mac = packet.eth.src
        self.dst_mac = packet.eth.dst

        #packet.ip
        self.src_ip = packet.ip.src
        self.dst_ip = packet.ip.dst

        #packet.tcp
        self.src_port = packet.tcp.srcport
        self.dst_port = packet.tcp.dstport

        # a to b var
        self.a2b_syn = 0
        self.a2b_sack_perm = 0
        self.a2b_ws = 0
        self.a2b_mss = 0

        self.a2b_rst = 0
        self.a2b_fin = 0

        # b to a var
        self.b2a_syn = 0
        self.b2a_sack_perm = 0
        self.b2a_ws = 0
        self.b2a_mss = 0

        self.b2a_rst = 0
        self.b2a_fin = 0
        self.update(packet)

    def find_direction(self, packet):
        if (self.src_ip == packet.ip.src) and (self.src_port == packet.tcp.srcport) and \
            (self.dst_ip == packet.ip.dst) and (self.dst_port == packet.tcp.dstport):
            #print("TRUE")
            return True
        else:
            #print("FALSE")
            return False

    def __update__(self, direction, packet):
        flag = int(packet.tcp.flags, 0)

        if direction:
            if flag & 0x02:
                self.a2b_syn = self.a2b_syn + 1
                #print(packet.tcp)
                print (type(packet.tcp.options.mss_val))
                '''
                self.a2b_sack_perm = packet.tcp.options.sack_perm
                self.a2b_ws = 0
                self.a2b_mss = 0
                '''
            if flag & 0x01:
                self.a2b_fin = self.a2b_fin + 1
            if flag & 0x04:
                self.a2b_rst = self.a2b_rst + 1
            #packet.tcp.ack
            #packet.tcp.seq
        else:
            if flag & 0x02:
                self.b2a_syn = self.b2a_syn + 1
                #print(packet.tcp)
                '''
                self.b2a_sack_perm = packet.tcp.options.sack_perm
                self.b2a_ws = 0
                self.b2a_mss = 0
                '''
            if flag & 0x01:
                self.b2a_fin = self.b2a_fin + 1
            if flag & 0x04:
                self.b2a_rst = self.b2a_rst + 1
        #self.print_packet(packet)

    def update(self, packet):
        self.__update__(self.find_direction(packet), packet)
        
    def print_session(self):
        print ("{} [{}] A({}:{}), B({}:{})".format(self.start_time, self.stream_id, self.src_ip, self.src_port, self.dst_ip, self.dst_port ))
        print ("[A to B] SYN:{},FIN:{},RST:{} | [B to A] SYN:{},FIN:{},RST:{}".format(
            self.a2b_syn, self.a2b_fin, self.a2b_rst, 
            self.b2a_syn, self.b2a_fin, self.b2a_rst))

    def print_packet(self, packet):
        print("{}:{}-{}:{}".format(packet.ip.src,packet.tcp.srcport, packet.ip.dst,packet.tcp.dstport))

def tcp_packet_handler(packet):
    stream_id = int(packet.tcp.stream, 0)
    if stream_id in traffic_meta_data:
        session = traffic_meta_data[stream_id]
        session.update(packet)
    else:
        traffic_meta_data[stream_id] = Session(packet)

def packet_handler(packet):
    for l in packet.layers:
        if "eth" == (l.layer_name):
            f_eth = 1
        if "ip" == (l.layer_name):
            f_ip = 1
        if "tcp" == (l.layer_name):
            f_tcp = 1

    if (f_eth == 1) and (f_ip == 1) and (f_tcp == 1):
        tcp_packet_handler(packet)

def print_report():
    for session in traffic_meta_data.values():
        session.print_session()
        print()

def start_program(path):
    print("= parsing start this file =")
    print(path)
    print()

    #packets = pyshark.FileCapture(path, use_json=True)
    packets = rdpcap(path)
    #print(packets.summary(), packets.show(), packets.sessions(), packets.conversations(), packets.listname)
    #print(dir(packets))
    cnt = 0
    for packet in packets:
        if 'TCP' in packet:
            print("show ethernet")
            eth = packet['Ethernet']
            eth.show()
            
            print("show ip")
            ip = packet['IP']
            packet.show()

            print("show tcp")
            tcp = packet['TCP']
            tcp.show()
            print()
            #packet_handler(packet)
        cnt = cnt + 1
        if cnt > 0:
                break

    print()
    print("= parsing done this file. = ")
    print( path)
    print()

    print_report()

def arguments_parse():
    parser = argparse.ArgumentParser(description='TCP analysis from pcap file.')
    parser.add_argument("-p", required=True, nargs='+', dest='paths',
                        help='target pcap file paths(use Absolute path)')
    args = parser.parse_args()

    for path in args.paths:
        if os.path.exists(path) == True:
            start_program(path)
        else:
            print("This file or path is not exists.", path)

if __name__ == "__main__":
    global traffic_meta_data
    traffic_meta_data = {}
    arguments_parse()

