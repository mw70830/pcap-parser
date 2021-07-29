#!/usr/bin/python3
# -*- coding: utf-8 -*-
import argparse
import os

def start_program(path):
    print(type(path), path)
    pass

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
    arguments_parse()
