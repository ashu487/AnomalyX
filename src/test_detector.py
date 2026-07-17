from detector import AnomalyDetector

# Create detector object
detector = AnomalyDetector()

# Test IP
src_ip = "192.168.1.100"

for i in range(205):
    alert = detector.detect_traffic_spike()

    print(f"Packet {i+1}")

    if alert:
        print(alert)