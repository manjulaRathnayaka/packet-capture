import pcap
import dpkt
import os

def capture_packets(interface):
    pc = pcap.pcap(name=interface, promisc=True, immediate=True, timeout_ms=50)
    for timestamp, packet in pc:
        eth = dpkt.ethernet.Ethernet(packet)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                if tcp.dport == 80 or tcp.sport == 80:  # HTTP port
                    print(f'Timestamp: {timestamp}')
                    print(f'Source IP: {pcap.ntoa(ip.src)}')
                    print(f'Destination IP: {pcap.ntoa(ip.dst)}')
                    print(f'TCP Data: {tcp.data}')

if __name__ == "__main__":
    interfaces = os.listdir('/sys/class/net/')
    for interface in interfaces:
        if interface != 'lo':  # Skip the loopback interface
            try:
                print(f'Capturing on interface: {interface}')
                capture_packets(interface)
            except Exception as e:
                print(f'Error capturing on interface {interface}: {e}')

