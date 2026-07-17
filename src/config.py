"""
Configuration settings for the Network Traffic Analyzer.
"""
# Network interface to sniff on. 
# Set to a specific interface name (e.g., 'eth0', 'wlan0', 'Ethernet') or None to use Scapy's default.
INTERFACE = None

import os
# Point directly to the AnomalyX database so the machine learning models can read the packets!
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILENAME = os.path.join(base_dir, "database", "network.db")

# Flask API settings
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000

# BPF (Berkeley Packet Filter) string for capturing specific traffic.
# Example: "tcp port 80" or "icmp". Default is empty (capture all).
CAPTURE_FILTER = ""
