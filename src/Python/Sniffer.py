import sys
import scapy.all as scapy
import binascii


def sniff(packet) -> None:
    """
    this function sniffs packets

    :param packet: scapy packet
    """
    try:

        if packet.haslayer(scapy.TCP):

            with open("packets.txt", "a") as file:

                file.write("{ "
                           + f"source_ip: {packet[scapy.IP].src} "
                           + f"dest_ip: {packet[scapy.IP].dst} "
                           + f"source_port: {packet[scapy.TCP].sport} "
                           + f"dst_prt: {packet[scapy.TCP].dport} "
                           + f"timestamp: {packet[scapy.TCP].options[2][1][0]} "
                           + f"total_length: {len(packet)} "
                           + f"cache_flag: {packet[scapy.TCP].flags & (1 << 12)} "
                           + f"steps_flag: {packet[scapy.TCP].flags & (1 << 11)} "
                           + f"type_flag: {packet[scapy.TCP].flags & (1 << 12)} "
                           + f"status_code: {packet[scapy.TCP].flags & ((1 << 10) - 1)} "
                           + f"cache_control: {packet[scapy.TCP].flags & (1 << 12)} "
                           + f"data: {binascii.hexlify(packet[scapy.Raw].load) if packet.haslayer(scapy.Raw) else 'No Data'} "

                           +"}\n")

        print(packet)

    except KeyboardInterrupt:
        print("\nStopping sniffer...")
        sys.exit(0)


def main():
    scapy.sniff(prn=sniff, filter="tcp or udp or icmp or igmp", iface="lo")


if __name__ == "__main__":
    main()
