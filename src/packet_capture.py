from scapy.all import sniff
packets = sniff(count=5)

for packet in packets:
    print(packet.summary())