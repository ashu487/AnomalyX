from collections import defaultdict
from datetime import datetime, timedelta


class AnomalyDetector:

    def __init__(self):
        # Stores (destination_port, timestamp) for each source IP
        self.port_activity = defaultdict(list)  # Port scan detection
        self.syn_activity = defaultdict(list)   # SYN flood detection (only timestamps)
        self.icmp_activity = defaultdict(list) #icmp detection
        self.packet_times = []     #traffic spike detection count the number of packets


        
        # State tracking for active alerts to prevent spamming
        self.active_port_scans = set()
        self.active_syn_floods = set()
        self.active_icmp_floods = set()
        self.traffic_spike_active = False

        # Detection settings
        self.PORT_SCAN_THRESHOLD = 10      # More than 10 ports
        self.SYN_THRESHOLD = 50           # More than 50 SYN packets
        self.TIME_WINDOW = timedelta(seconds=10)   # Within 10 seconds
        self.ICMP_THRESHOLD = 5 #100 icmp packets //CHANGEEEE AGAIN TO 100
        self.TRAFFIC_SPIKE_THRESHOLD = 30 #more than 200 packets in 10 seconds raise alert

    def detect_port_scan(self, src_ip, dst_port):
        """
        Detects if a source IP is scanning multiple destination ports
        within a short time window.

        Returns:
            Dictionary -> Port scan detected
            None -> Normal traffic
        """

        current_time = datetime.now()

        # Store current packet information
        self.port_activity[src_ip].append((dst_port, current_time))

        # Remove old packets outside the time window
        self.port_activity[src_ip] = [
            (port, timestamp)
            for port, timestamp in self.port_activity[src_ip]
            if current_time - timestamp <= self.TIME_WINDOW
        ]

        # Count unique destination ports
        unique_ports = {
            port for port, timestamp in self.port_activity[src_ip]
        }

        # Check if threshold exceeded
        if len(unique_ports) >= self.PORT_SCAN_THRESHOLD:

            if src_ip not in self.active_port_scans:
                self.active_port_scans.add(src_ip)
                return {
                    "attack": "Port Scan",
                    "severity": "High",
                    "message": (
                        f"{src_ip} scanned {len(unique_ports)} ports "
                        f"in {self.TIME_WINDOW.seconds} seconds"
                    )
                }
            return None
        else:
            if src_ip in self.active_port_scans:
                self.active_port_scans.remove(src_ip)


        return None

    def detect_syn_flood(self, src_ip):
        """
        Detect SYN Flood attack.
        """

        current_time = datetime.now()

        # Store timestamp
        self.syn_activity[src_ip].append(current_time)

        # Keep only packets within the time window
        self.syn_activity[src_ip] = [
            timestamp
            for timestamp in self.syn_activity[src_ip]
            if current_time - timestamp <= self.TIME_WINDOW
        ]

        # Count SYN packets
        syn_count = len(self.syn_activity[src_ip])

        if syn_count >= self.SYN_THRESHOLD:

            if src_ip not in self.active_syn_floods:
                self.active_syn_floods.add(src_ip)
                return {
                    "attack": "SYN Flood",
                    "severity": "Critical",
                    "message": (
                        f"{src_ip} sent {syn_count} SYN packets "
                        f"in {self.TIME_WINDOW.seconds} seconds"
                    )
                }
            return None
        else:
            if src_ip in self.active_syn_floods:
                self.active_syn_floods.remove(src_ip)

        return None
    def detect_icmp_flood(self, src_ip):
        """
        Detect ICMP Flood attack.
        """

        current_time = datetime.now()

        # Store timestamp
        self.icmp_activity[src_ip].append(current_time)

        # Keep only packets within the time window
        self.icmp_activity[src_ip] = [
            timestamp
            for timestamp in self.icmp_activity[src_ip]
            if current_time - timestamp <= self.TIME_WINDOW
        ]

        # Count ICMP packets
        icmp_count = len(self.icmp_activity[src_ip])
        if icmp_count >= self.ICMP_THRESHOLD:

            if src_ip not in self.active_icmp_floods:
                self.active_icmp_floods.add(src_ip)
                return {
                    "attack": "ICMP Flood",
                    "severity": "Medium",
                    "message": (
                        f"{src_ip} sent {icmp_count} ICMP packets "
                        f"in {self.TIME_WINDOW.seconds} seconds"
                    )
                }
            return None
        else:
            if src_ip in self.active_icmp_floods:
                self.active_icmp_floods.remove(src_ip)

        return None

    def detect_traffic_spike(self):
        """
        Detect sudden spikes in overall network traffic.
        """

        current_time = datetime.now()

        # Store current packet timestamp
        self.packet_times.append(current_time)

        # Remove old timestamps
        self.packet_times = [
            timestamp
            for timestamp in self.packet_times
            if current_time - timestamp <= self.TIME_WINDOW
        ]

        packet_count = len(self.packet_times)

        if packet_count > self.TRAFFIC_SPIKE_THRESHOLD:

            if not self.traffic_spike_active:
                self.traffic_spike_active = True
                return {
                    "attack": "Traffic Spike",
                    "severity": "Medium",
                    "message": (
                        f"Network traffic reached {packet_count} packets "
                        f"in {self.TIME_WINDOW.seconds} seconds"
                    )
                }
            return None
        else:
            self.traffic_spike_active = False

        return None