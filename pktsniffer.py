import argparse

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

if __name__ == "__main__":
    args = parse_arguments()