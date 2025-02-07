# Packet Sniffer

## Author: Ajinkya Shetty (as8856)

This is a simple packet sniffer script that processes `.pcap` files and filters packets based on user-defined criteria. The script is implemented in Python using the `scapy` library.

## Features
- Reads and parses `.pcap` files.
- Filters packets by IP address, port, protocol (TCP, UDP, ICMP), and network.
- Displays detailed information about Ethernet, IP, and transport layer headers.

## Requirements
- Python 3.x
- `scapy` library

You can install `scapy` using pip:
```bash
pip install scapy


Usage
Command-line Arguments
-r, --file <path>: Path to the .pcap file (required).
-c, --count <number>: Limit the number of packets to analyze (optional).
--host <IP address>: Filter packets by source IP address (optional).
--port <port number>: Filter packets by source or destination port number (optional).
--tcp: Filter only TCP packets (optional).
--udp: Filter only UDP packets (optional).
--icmp: Filter only ICMP packets (optional).
--net <network>: Filter packets by network (e.g., 192.168.1.0/24) (optional).

To analyze a .pcap file and display all packets:

python pktsniffer.py -r packets.pcap 

To filter only TCP packets:

python pktsniffer.py -r packets.pcap  --tcp

To display only packets from a specific IP address:

python packet_sniffer.py -r path_to_file.pcap --host 192.168.1.121

To limit the number of packets analyzed:
python packet_sniffer.py -r path_to_file.pcap -c 10

To filter packets by network:

python packet_sniffer.py -r path_to_file.pcap --net 192.168.1.1