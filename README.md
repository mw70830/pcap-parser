# pcap-parser
packetdump analyzer.
developed on ubuntu 18.04, python3.

# spec
1. analyze session and print session(tcp stream)
2. exists of SYN/FIN/RST
3. exists of invalid ack.

# usage
```
python3 pcap-parser-main.py -p [dump file's path]
 ex) python3 pcap-parser-main.py -p ../pcap-sample/packetDump_test.pcap
```

# output
```
root@local:~/pcap-parser$ python3 pcap-parser-main.py -p ../pcap-sample/packetDump_test.pcap

= parsing start this file =
../pcap-sample/packetDump_test.pcap

now on parsing, each packet.
>> 200

= parsing done this file. =
../pcap-sample/packetDump_test.pcap

[2] 2021-07-18 20:54:23.974544 A(1.1.1.1:34324), B(1.1.1.2:443)
  [A to B] SYN:1,FIN:1,RST:0 | [B to A] SYN:1,FIN:1,RST:0
```

# required packages
```
install 'pyshark' module --> pip3 install pyshark
install 'tshark' --> apt install tshark
```
