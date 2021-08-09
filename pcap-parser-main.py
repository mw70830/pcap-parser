#!/usr/bin/python3
# -*- coding: utf-8 -*-
import argparse
from ctypes import *
import os
import pyshark
from enum import IntEnum

class TcpFlags(IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

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

        self.complete_a_to_b = 0
        self.complete_b_to_a = 0

        self.occur_partial_seq_a_to_b = 0
        self.occur_partial_ack_a_to_b = 0
        self.occur_reverse_ack_a_to_b = 0

        self.occur_partial_seq_b_to_a = 0
        self.occur_partial_ack_b_to_a = 0
        self.occur_reverse_ack_b_to_a = 0

        self.update(packet)

    def find_direction(self, packet):
        if (self.src_ip == packet.ip.src) and (self.src_port == packet.tcp.srcport) and \
            (self.dst_ip == packet.ip.dst) and (self.dst_port == packet.tcp.dstport):
            return True
        else:
            return False

    def __update__(self, direction, packet):
        flag = int(packet.tcp.flags, 0)

        seq = int(packet.tcp.seq, 0)
        ack = int(packet.tcp.ack, 0)
        tcp_len = int(packet.tcp.len, 0)

        #print(f'{seq}, {ack}, {tcp_len}' )

        if direction:
            # A to B
            if flag & TcpFlags.SYN:
                self.a2b_syn = self.a2b_syn + 1
                #print(packet.tcp)
                #print (type(packet.tcp.options.mss_val))
                '''
                self.a2b_sack_perm = packet.tcp.options.sack_perm
                self.a2b_ws = 0
                self.a2b_mss = 0
                '''
            if flag & TcpFlags.FIN:
                self.a2b_fin = self.a2b_fin + 1
            if flag & TcpFlags.RST:
                self.a2b_rst = self.a2b_rst + 1

            '''
            a 가 b로 보낸데이터에서 점검할 사항.

            * input
            a seq, seq + tcp len
            b ack

            * update
            self.progress_a_to_b = [[seq,seq + tcp_len], ... ]
            self.complete_b_to_a = int (마지막 받은 ack)

            self.occur_partial_seq_a_to_b
            self.occur_partial_ack_a_to_b
            self.occur_reverse_ack_a_to_b
            '''

            # complete_b_to_a니까 a의 ack로 계산한다.
            if self.complete_b_to_a < ack:
                self.complete_b_to_a = ack
            elif self.complete_b_to_a > ack:
                self.occur_reverse_ack_a_to_b = self.occur_reverse_ack_a_to_b + 1

            # progress_a_to_b
            # TODO. 진행중인 단계 개발 해야함.

        else:
            # B to A
            if flag & TcpFlags.SYN:
                self.b2a_syn = self.b2a_syn + 1
                #print(packet.tcp)
                '''
                self.b2a_sack_perm = packet.tcp.options.sack_perm
                self.b2a_ws = 0
                self.b2a_mss = 0
                '''
            if flag & TcpFlags.FIN:
                self.b2a_fin = self.b2a_fin + 1
            if flag & TcpFlags.RST:
                self.b2a_rst = self.b2a_rst + 1

            # complete_a_to_b니까 b의 ack로 계산한다.
            if self.complete_a_to_b < ack:
                self.complete_a_to_b = ack
            elif self.complete_a_to_b > ack:
                self.occur_reverse_ack_b_to_a = self.occur_reverse_ack_b_to_a + 1


    def update(self, packet):
        self.__update__(self.find_direction(packet), packet)

    def check_printable(self):
        return True
        if self.occur_reverse_ack_b_to_a > 0 or self.occur_reverse_ack_a_to_b > 0:
            return True
        else:
            return False

    def print_session(self):
        if self.check_printable() == True:
            print ("[{}] {} A({}:{}), B({}:{})".format(self.stream_id, self.start_time, self.src_ip, self.src_port, self.dst_ip, self.dst_port ))
            print ("  [A to B] SYN:{},FIN:{},RST:{} | [B to A] SYN:{},FIN:{},RST:{}".format(
                self.a2b_syn, self.a2b_fin, self.a2b_rst,
                self.b2a_syn, self.b2a_fin, self.b2a_rst))
            if self.occur_reverse_ack_b_to_a > 0:
                print (f"  [WARNING] reverse ack, In the data going from b to a : {self.occur_reverse_ack_b_to_a}")
            if self.occur_reverse_ack_a_to_b > 0:
                print (f"  [WARNING] reverse ack, In the data going from a to b : {self.occur_reverse_ack_a_to_b}")

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

    # parsing only TCP packets.
    if (f_eth == 1) and (f_ip == 1) and (f_tcp == 1):
        tcp_packet_handler(packet)

def print_report():
    for session in traffic_meta_data.values():
        session.print_session()

def parsing_start(path):
    print_start_comment(path)

    packets = pyshark.FileCapture(path, use_json=True)
    pkt_count = 0
    print("now on parsing, each packet.")
    for packet in packets:
        packet_handler(packet)
        print(f'>> {pkt_count}', end = "\r")
        pkt_count = pkt_count + 1

    print_end_comment(path)

    print_report()

def print_end_comment(path):
    print("\n")
    print("= parsing done this file. = ")
    print( path)
    print()

def print_start_comment(path):
    print("= parsing start this file =")
    print(path)
    print()

def start_program():
    # arguments parse
    parser = argparse.ArgumentParser(description='TCP analysis from pcap file.')
    parser.add_argument("-p", required=True, nargs='+', dest='paths',
                        help='target pcap file paths(use Absolute path)')
    args = parser.parse_args()

    for path in args.paths:
        if os.path.exists(path) == True:
            parsing_start(path)
        else:
            print("This file or path is not exists.", path)

if __name__ == "__main__":
    # init global var
    global traffic_meta_data
    traffic_meta_data = {}

    # start program
    start_program()
