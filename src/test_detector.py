from detector import AnomalyDetector

# Create detector object
detector = AnomalyDetector()

# Test IP
src_ip = "192.168.1.100"

for i in range(205):
    alert = detector.detect_traffic_spike()
    if alert:
        print(f"\n[Packet {i+1}] {alert}")

print("\n--- Simulating Port Scan ---")
for port in range(80, 95):  # 15 unique ports (threshold is 10)
    alert = detector.detect_port_scan(src_ip, port)
    if alert:
        print(f"\n[Port {port}] {alert}")

print("\n--- Simulating SYN Flood ---")
for i in range(55): # Threshold is 50
    alert = detector.detect_syn_flood(src_ip)
    if alert:
        print(f"\n[Packet {i+1}] {alert}")

print("\n--- Simulating ICMP Flood ---")
for i in range(105): # Threshold is 100
    alert = detector.detect_icmp_flood(src_ip)
    if alert:
        print(f"\n[Packet {i+1}] {alert}")