#!/usr/bin/python3
# -*- coding: utf-8 -*-
import argparse
import os
import pyshark

class Session:
    def __init__(self, packet):
        # FIXED DATA
        self.start_time = packet.sniff_time
        self.stream_id = packet.tcp.stream

        #packet.eth
        self.src_mac = packet.eth.src
        self.dst_mac = packet.eth.dst

        #packet.ip
        self.src_ip = packet.ip.src
        self.dst_ip = packet.ip.dst

        #packet.tcp
        self.src_port = packet.tcp.srcport
        self.dst_port = packet.tcp.dstport

    def find_direction(self, packet):
        if self.ip_src == packet.ip.src:
            return True
        return False

    def update(self, packet):

        pass

    def print_session(self):
        print ("{} [{}] {}:{}, {}:{}".format(self.start_time, self.stream_id, self.src_ip, self.src_port, self.dst_ip, self.dst_port ))


def tcp_packet_handler(packet):
    if packet.tcp.stream in traffic_meta_data:
        session = traffic_meta_data[packet.tcp.stream]
        session.update(packet)
    else:
        traffic_meta_data[packet.tcp.stream] = Session(packet)

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

def start_program(path):
    print("= parsing start this file =")
    print(path)
    print()

    packets = pyshark.FileCapture(path, use_json=True)
    for packet in packets:
        packet_handler(packet)

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
