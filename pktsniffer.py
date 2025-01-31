import argparse
from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP

def parse_arguments():
    """Parses command-line arguments using argparse."""
    parser = argparse.ArgumentParser(description="A simple packet sniffer for pcap files.")
    parser.add_argument("-r", "--file", required=True, help="Path to the .pcap file")
    parser.add_argument("-c", "--count", type=int, help="Limit the number of packets analyzed")
    parser.add_argument("--host", help="Filter packets by host IP address")
    parser.add_argument("--port", type=int, help="Filter packets by port number")
    parser.add_argument("--tcp", action="store_true", help="Filter only TCP packets")
    parser.add_argument("--udp", action="store_true", help="Filter only UDP packets")
    parser.add_argument("--icmp", action="store_true", help="Filter only ICMP packets")
    parser.add_argument("--net", help="Filter packets by network (e.g., 192.168.1.0/24)")
    return parser.parse_args()

def parse_ethernet(pkt):
    """Parses Ethernet header."""
    eth = pkt[Ether]
    return len(pkt), eth.dst, eth.src, hex(eth.type)

def parse_ip(pkt):
    """Parses IP header."""
    ip = pkt[IP]
    return ip.version, ip.ihl, ip.tos, ip.len, ip.id, ip.flags, ip.frag, ip.ttl, ip.proto, ip.chksum, ip.src, ip.dst

if __name__ == "__main__":
    args = parse_arguments()