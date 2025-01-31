import argparse
from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP
from ipaddress import ip_network, ip_address

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

def parse_transport(pkt):
    """Parses TCP, UDP, or ICMP headers."""
    if TCP in pkt:
        tcp = pkt[TCP]
        return f"TCP: Src Port={tcp.sport}, Dst Port={tcp.dport}, Flags={tcp.flags}"
    elif UDP in pkt:
        udp = pkt[UDP]
        return f"UDP: Src Port={udp.sport}, Dst Port={udp.dport}"
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        return f"ICMP: Type={icmp.type}, Code={icmp.code}, Checksum={icmp.chksum}"
    return "Other Protocol"

def process_pcap(file_path, args):
    """Processes packets from a pcap file with filtering."""
    packets = rdpcap(file_path)
    count = 0

    for i, pkt in enumerate(packets):
        if args.count and count >= args.count:
            break  # Stop after reaching the packet limit
        # if not packet_matches_filter(pkt, args):
        #     continue  # Skip packets that don't match the filter
        print(f"\nPacket {i + 1}:")
        if Ether in pkt:
            pkt_size, dst_mac, src_mac, eth_type = parse_ethernet(pkt)
            print(f"  Ethernet: Size={pkt_size} bytes, Dst MAC={dst_mac}, Src MAC={src_mac}, Type={eth_type}")
        if IP in pkt:
            (version, ihl, tos, length, ident, flags, frag_offset, ttl, proto, checksum, src_ip, dst_ip) = parse_ip(pkt)
            print(f"  IP: Version={version}, IHL={ihl}, TOS={tos}, Length={length}, ID={ident}, Flags={flags}, "
                  f"Fragment Offset={frag_offset}, TTL={ttl}, Protocol={proto}, Checksum={checksum}, Src={src_ip}, Dst={dst_ip}")
        print(f"  {parse_transport(pkt)}")
        count += 1


if __name__ == "__main__":
    args = parse_arguments()
    process_pcap(args.file, args)