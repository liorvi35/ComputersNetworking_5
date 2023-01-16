#include <stdio.h> // standard
#include <stdlib.h> // exit
#include <pcap.h> // packet capturing
#include <netinet/ip.h> // ip header
#include <netinet/tcp.h> // tcp header
#include <net/ethernet.h> // ethernet header
#include <errno.h> // last error number
#include <string.h> // memset

/* just for comfort */
#define PROMISCUSE_MODE 1 
#define NON_PROMISCUSE_MODE 0
#define DONT_STOP_CAPTURE -1

/* how many packets has been received*/
long packet_num = 0;

/* printing each field in ethernet header */
void print_ethernet_header(struct ether_header *eth)
{  
    printf("------------------ ETHERNET II -------------------\n");
    printf("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("Type: %s\n", ntohs(eth->ether_type) == 0x0800 ? "IPv4 (0x0800)" : "UNKNOWN");
}

/* printing each field in ip header */
void print_ip_header(struct iphdr *ip)
{
    printf("--------------- Internet Protocol ----------------\n");
    printf("Version: %u\n", ip->version);
    printf("Header Length: %u bytes\n", ip->ihl);
    printf("Total Length: %u\n", ip->tot_len);
    printf("Indentification: 0x%04x (%d)\n", ip->id, ip->id);
    printf("Fragment Offset: %u\n", ip->frag_off);
    printf("Time to Live: %u\n", ip->ttl);
    printf("Protocol: %s (%d)\n", (ip->protocol == IPPROTO_TCP ? "TCP" : "UNKNOWN"), ip->protocol);
    printf("Header Checksum: 0x%04x [validation %s]\n", ntohs(ip->check), (ntohs(ip->check) == 0 ? "enabled" : "disabled"));
    printf("Source Address: %s\n", inet_ntoa(*((struct in_addr*)&ip->saddr)));
    printf("Destination Address: %s\n", inet_ntoa(*((struct in_addr*)&ip->daddr)));
}

/* printing each field in tcp header */
void print_tcp_header(struct tcphdr *tcp, struct iphdr *ip)
{
    printf("--------- Transmition Control Protocol ----------\n");
    printf("Source Port: %u\n", ntohs(tcp->source));
    printf("Destination Port: %u\n", ntohs(tcp->dest));
    printf("TCP Segment Len: %u\n",  htons(ip->tot_len) - tcp->doff * 4);
    printf("Sequence Number: %u\n", ntohl(tcp->seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp->ack));
    printf("Header Length: %u bytes\n", tcp->doff * 4);
    printf("Flags: FIN = %u, SYN = %u, RST = %u, PSH = %u, ACK = %u, URG = %u\n", 
            tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg);
    printf("Window: %u\n", ntohs(tcp->window));
    printf("Checksum: %u\n", ntohs(tcp->check));
    printf("Urgent Pointer: %u\n", ntohs(tcp->urg_ptr));
}

/* printing each field in ethernet header */
void print_app_header()
{
    // TODO: printf cache_flag, steps_flag, type_flag, status_code, cahce_control
    // find their placec by the picture of the packet from ex2
}

void print_payload()
{
    // TODO: printf data (packets payload)
}

void packet_data(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_bytes)
{ 
    // ethearnet header
    struct ether_header *eth = (struct ether_header*)pkt_bytes;

    // ip header
    struct iphdr *ip = (struct iphdr*)(pkt_bytes + sizeof(struct ether_header*));

    // tcp headr
    struct tcphdr *tcp = (struct tcphdr*)(pkt_bytes + sizeof(struct ether_header*) + sizeof(struct iphdr*));

    // packets printing to user (console)
    printf("Packet Number - %ld\n", ++packet_num);
    print_ethernet_header(eth);
    print_ip_header(ip);
    print_tcp_header(tcp, ip);
    // print_app_header();
    // print_payload();
    printf("\n");


    // packets extracting (file)
    FILE *packets = fopen("213081763_213451818.txt", "a");
    fprintf(packets, "{ source_ip: %s, dest_ip: %s, source_port: %d, dest_port: %d, timestamp: %ld, total_length: %d, cache_flag: ?, steps_flag: ?, type_flag: ?, status_code: ?, cahce_control: ?, data: ? }\n",
            inet_ntoa(*((struct in_addr*)&ip->saddr)), inet_ntoa(*((struct in_addr*)&ip->daddr)), ntohs(tcp->source), ntohs(tcp->dest),
            (header->ts.tv_sec + header->ts.tv_usec / 1000000), header->len);
    fclose(packets);
}

int main(int argc, char *argv[])
{
    pcap_if_t *all_devs = NULL; // all network devices holder

    pcap_t *handle = NULL; // sniffer handler

    char err[PCAP_ERRBUF_SIZE] = {'\0'}, *device = NULL, *filter = NULL;

    struct bpf_program fp; // compiled filter
    memset(&fp, 0, sizeof(fp));

    bpf_u_int32 net = 0; // 

    /* finding all network devices */
    // all_devs[name] = {enp0s3, any, lo, bluetooth-monitor, nflog, nfqueue, dbus-system, dbus-session}
    if(pcap_findalldevs(&all_devs, err) < 0) 
    {
        fprintf(stderr, "pcap_findalldevs() failed with error code %d.\nerror message: %s.", errno, err);
        exit(EXIT_FAILURE);
    }
    device = all_devs->next->next->name;

    // oppening the device for packet capturing
    handle = pcap_open_live(device , IP_MAXPACKET, PROMISCUSE_MODE, 1000, err);
    if(handle == NULL)
    {
        fprintf(stderr, "pcap_open_live() failed with error code %d.\nerror message: %s.", errno, err);
        exit(EXIT_FAILURE);
    }

    // apllying sniffing filter
    filter = "tcp";
    if (pcap_compile(handle, &fp, filter, 0, net) < 0) 
    {
        fprintf(stderr, "pcap_compile() failed with error code: %d.\nerror message: %s", errno, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) < 0) 
    {
        fprintf(stderr, "pcap_setfilter() failed with error code: %d.\nerror message: %s", errno, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // what 
    printf("Sniffing from: \"%s\", with filters: \"%s\"...\n", device, filter);

    // packet proccessing
    pcap_loop(handle, DONT_STOP_CAPTURE, packet_data, NULL);

    // closing sniffer handler
    pcap_close(handle);

    // freeing all 
    pcap_freealldevs(all_devs);

    // exit without errors
    exit(EXIT_SUCCESS);
}
