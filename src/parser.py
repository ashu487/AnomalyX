"""
Packet parsing logic to extract relevant fields from Scapy packets.
"""
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet

def parse_packet(packet: Packet) -> dict:
    """
    Extracts relevant information from a Scapy packet.
    Returns a dictionary with extracted fields or None if the packet lacks an IP layer.
    """
    # We only care about IP packets for this basic analyzer
    if not packet.haslayer(IP):
        return None
    
    ip_layer = packet.getlayer(IP)
    
    data = {
        "timestamp": time.time(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": None,
        "dst_port": None,
        "protocol": "OTHER",
        "packet_size": len(packet),
        "tcp_flags": None
    }

    # Determine protocol and extract ports if applicable
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        data["src_port"] = tcp_layer.sport
        data["dst_port"] = tcp_layer.dport
        data["protocol"] = "TCP"
        data["tcp_flags"] = str(tcp_layer.flags)
    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        data["src_port"] = udp_layer.sport
        data["dst_port"] = udp_layer.dport
        data["protocol"] = "UDP"
    elif packet.haslayer(ICMP):
        data["protocol"] = "ICMP"
        
    return data
