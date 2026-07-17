from collections import defaultdict
from datetime import datetime, timedelta


class AnomalyDetector:
    def __init__(self):
        # Stores (destination_port, timestamp) for each source IP
        self.port_activity = defaultdict(list)

        # Detection settings
        self.PORT_SCAN_THRESHOLD = 10      # More than 10 ports
        self.TIME_WINDOW = timedelta(seconds=10)   # Within 10 seconds

    def detect_port_scan(self, src_ip, dst_port):
        """
        Detects if a source IP is scanning multiple destination ports
        within a short time window.

        Returns:
            True  -> Port scan detected
            False -> Normal traffic
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
        if len(unique_ports) > self.PORT_SCAN_THRESHOLD:
            return {
              "attack": "Port Scan",
              "severity": "High",
              "message": (f"{src_ip} scanned {len(unique_ports)} ports "f"in {self.TIME_WINDOW.seconds} seconds")
             }

        return None