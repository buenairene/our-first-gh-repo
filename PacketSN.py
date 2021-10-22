from scapy.all import sniff

def packet_capture(network_packet):
    print(network_packet.show())

def main():
    sniff(prn=packet_capture, count=2)

if __name__ == '__main__':
    main()

