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


/* application header */
struct apphdr
{
    uint32_t unixtime;
    uint16_t length;

    union
    {
        uint16_t flags;
        uint16_t _:3, cache_flag:1, steps_flag:1, type_flag:1, status_code:10;
    };
   
    uint16_t cache_control;
    uint16_t __;
};





/* printing each field in ethernet header */
void print_ethernet_header(const struct ether_header *eth)
{   
    printf("------------------ ETHERNET II -------------------\n");
    printf("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("Type: %s\n", ntohs(eth->ether_type) == 0x0800 ? "IPv4 (0x0800)" : "UNKNOWN");
}

/* printing each field in ip header */
void print_ip_header(const struct iphdr *ip, FILE *packets)
{
    printf("--------------- Internet Protocol ----------------\n");
    printf("Version: %u\n", ip->version);
    printf("Header Length: %u bytes (%u)\n", 4 * ip->ihl, ip->ihl);
    printf("Total Length: %u\n", ntohs(ip->tot_len));
    printf("Indentification: 0x%04x (%u)\n", ntohs(ip->id), ntohs(ip->id));
    printf("Fragment Offset: %u\n", ntohs(ip->frag_off) & 0x1fff);
    printf("Time to Live: %u\n", ip->ttl);
    printf("Protocol: %s (%u)\n", (ip->protocol == IPPROTO_TCP ? "TCP" : "UNKNOWN"), ip->protocol);
    printf("Header Checksum: 0x%04x [validation %s]\n", ntohs(ip->check), (ntohs(ip->check) == 0 ? "enabled" : "disabled"));
    printf("Source Address: %s\n", inet_ntoa(*((struct in_addr*)&ip->saddr)));
    printf("Destination Address: %s\n", inet_ntoa(*((struct in_addr*)&ip->daddr)));


    fprintf(packets, "{ source_ip: %s, dest_ip: %s,", inet_ntoa(*((struct in_addr*)&ip->saddr)), inet_ntoa(*((struct in_addr*)&ip->daddr)));
}

/* printing each field in tcp header */
int print_tcp_header(const struct tcphdr *tcp, unsigned int ip_size, FILE *packets)
{
    printf("--------- Transmition Control Protocol ----------\n");
    printf("Source Port: %u\n", ntohs(tcp->source));
    printf("Destination Port: %u\n", ntohs(tcp->dest));
    printf("TCP Segment Len: %u\n", htons(tcp->doff) * 4);
    printf("Sequence Number (raw): %u\n", ntohl(tcp->seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp->ack_seq));
    printf("Header Length: %u bytes\n", tcp->doff * 4);
    printf("Flags: FIN = %u, SYN = %u, RST = %u, PSH = %u, ACK = %u, URG = %u\n", 
            tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg);
    printf("Window: %u\n", ntohs(tcp->window));
    printf("Checksum: 0x%04x [%s]\n", ntohs(tcp->check), (ntohs(tcp->check) == 0 ? "verified" : "unverified"));
    printf("Urgent Pointer: %u\n", ntohs(tcp->urg_ptr));

    fprintf(packets, " source_port: %u, dest_port: %u,", ntohs(tcp->source), ntohs(tcp->dest));

    if(tcp->psh)
    {
        return 1;
    }
    return 0;
}

/* printing each field in ethernet header */
void print_app_header(const struct pcap_pkthdr *header, const u_char *pkt_bytes, struct apphdr *app, FILE *packets)
{
    app->flags = ntohs(app->flags);
    uint16_t cache_flag = ((app->flags) >> 12) & 1;
    uint16_t steps_flag = ((app->flags) >> 11) & 1;
    uint16_t type_flag = ((app->flags) >> 10) & 1;
    uint16_t status_code = app->status_code;
    uint16_t cache_control = ntohs(app->cache_control);
    printf("--------- Application Header ----------\n");
    printf("timestamp: %ld (seconds)\n", (header->ts.tv_sec + (header->ts.tv_usec / 1000000)));
    printf("total length: %d\n", header->len);
    printf("cache flag: %hu\n", cache_flag);
    printf("steps flag: %hu\n", steps_flag);
    printf("type flag: %hu\n", type_flag);
    printf("status code: %hu\n", status_code);
    printf("cache control: %hu\n", cache_control);

    fprintf(packets, " timestamp: %ld, total_length: %d, cache_flag: %hu, steps_flag: %hu, type_flag: %hu, status_code: %hu, cache_control: %hu"
            ,(header->ts.tv_sec + (header->ts.tv_usec / 1000000)), header->len, cache_flag, steps_flag, type_flag, status_code, cache_control);
}

void print_payload(const struct pcap_pkthdr *header, const u_char *pkt_bytes, struct apphdr *app, struct iphdr* ip, struct tcphdr* tcp, FILE *packets)
{   
    uint16_t app_length = ntohs(app->length);
    const u_char *payload = (pkt_bytes + sizeof(struct ether_header) + ip->ihl * 4 + tcp->doff * 4) + 12;
    printf("--------- Payload ----------\n");
    fprintf(packets, ", \ndata:");
    for(int i = 0; i < app_length; ++i)
    {
        if(!(i & 15))
        {
            printf("\n%04X: ", i);
            fprintf(packets, "\n%04X: ", i);
        }
        printf("%02X ", ((unsigned char*)payload)[i]);
        fprintf(packets, "%02X ", ((unsigned char*)payload)[i]);
    }
    printf("\n");
    fprintf(packets, " }\n\n");
}

void packet_data(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_bytes)
{ 
    struct ether_header *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct apphdr *app;

    eth = (struct ether_header*)pkt_bytes;
    ip = (struct iphdr*)(pkt_bytes + sizeof(struct ether_header));
    tcp = (struct tcphdr*)(pkt_bytes + sizeof(struct ether_header) + sizeof(struct iphdr));
    app = (struct apphdr*)(pkt_bytes + sizeof(struct ether_header) + ip->ihl * 4 + tcp->doff * 4);

    int x = 0;

    FILE *packets = fopen("213081763_213451818.txt", "a");

    //packets printing to user (console)
    printf("Packet Number - %ld\n", ++packet_num);
    print_ethernet_header(eth);
    print_ip_header(ip, packets);
    x = print_tcp_header(tcp, ip->tot_len, packets);
    print_app_header(header, pkt_bytes, app, packets);
    if(x)
    {
        print_payload(header, pkt_bytes, app, ip, tcp, packets);
    }
    else
    {
        fprintf(packets, " data: NOT-A-PSH }\n\n");
        printf("--------- Payload ----------\nNOT-A-PSH\n");
    }
    printf("\n");

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
        fprintf(stderr, "pcap_findalldevs() failed with error code %d.\nerror message: %s.\n", errno, err);
        exit(EXIT_FAILURE);
    }
    device = all_devs->next->next->name;

    // oppening the device for packet capturing
    handle = pcap_open_live(device , IP_MAXPACKET, PROMISCUSE_MODE, 1000, err);
    if(handle == NULL)
    {
        fprintf(stderr, "pcap_open_live() failed with error code %d.\nerror message: %s.\n", errno, err);
        exit(EXIT_FAILURE);
    }

    // apllying sniffing filter
    filter = "tcp";
    if (pcap_compile(handle, &fp, filter, 0, net) < 0) 
    {
        fprintf(stderr, "pcap_compile() failed with error code: %d.\nerror message: %s.\n", errno, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) < 0) 
    {
        fprintf(stderr, "pcap_setfilter() failed with error code: %d.\nerror message: %s.\n", errno, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // what 
    printf("Sniffing from: \"%s\", with filters: \"%s\"...\n\n", device, filter);

    // packet proccessing
    pcap_loop(handle, DONT_STOP_CAPTURE, packet_data, NULL);

    // closing sniffer handler
    pcap_close(handle);

    // freeing all 
    pcap_freealldevs(all_devs);

    // exit without errors
    exit(EXIT_SUCCESS);
}
