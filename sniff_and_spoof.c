#include <stdio.h>        // standard
#include <stdlib.h>       // exit
#include <pcap.h>         // packet capturing
#include <netinet/ip.h>   // ip header
#include <netinet/tcp.h>  // tcp header
#include <net/ethernet.h> // ethernet header
#include <errno.h>        // last error number
#include <string.h>       // memset
#include <netinet/ip_icmp.h>
#include <bits/types.h>
#include <unistd.h>


/* just for comfort */
#define PROMISCUSE_MODE 1
#define NON_PROMISCUSE_MODE 0
#define DONT_STOP_CAPTURE -1

/* how many packets has been received*/
long packet_num = 0;

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result = 0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void packet_data(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_bytes)
{
    struct iphdr *ip_req;

    ip_req = (struct iphdr*)(pkt_bytes + sizeof(struct ether_header));

    char replay_pack[IP_MAXPACKET] = {'\0'};

    struct icmphdr *icmp = (struct icmphdr *)(replay_pack + sizeof(struct iphdr));

    icmp->type = 0;
    icmp->checksum = 0;
    icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr));

    struct iphdr *ip = (struct iphdr *)replay_pack;
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 20;
    ip->saddr = ip_req->daddr;
    ip->daddr = ip_req->saddr;
    ip->protocol = IPPROTO_ICMP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock <= 0)
    {
        perror("socket() failed");
        exit(1);
    }

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)))
    {
        perror("setsockopt() failed");
        close(sock);
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->daddr;

    size_t s = sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *)&addr, sizeof(addr));

    if (s < 0)
    {
        perror("sendto() failed");
        close(sock);
        exit(1);
    }
    else if (s == 0)
    {
        fprintf(stderr, "send 0 bytes!\n");
        close(sock);
        exit(1);
    }

    printf("Repley has been send to: %s\n", inet_ntoa(*((struct in_addr*)&ip_req->saddr)));
    close(sock);
}

    int main()
    {
        pcap_if_t *all_devs = NULL; // all network devices holder

        pcap_t *handle = NULL; // sniffer handler

        char err[PCAP_ERRBUF_SIZE] = {'\0'}, *device = NULL, *filter = NULL;

        struct bpf_program fp; // compiled filter
        memset(&fp, 0, sizeof(fp));

        bpf_u_int32 net = 0; //

        /* finding all network devices */
        // all_devs[name] = {enp0s3, any, lo, bluetooth-monitor, nflog, nfqueue, dbus-system, dbus-session}
        if (pcap_findalldevs(&all_devs, err) < 0)
        {
            fprintf(stderr, "pcap_findalldevs() failed with error code %d.\nerror message: %s.\n", errno, err);
            exit(EXIT_FAILURE);
        }
        device = all_devs->name;

        // oppening the device for packet capturing
        handle = pcap_open_live(device, IP_MAXPACKET, PROMISCUSE_MODE, 1000, err);
        if (handle == NULL)
        {
            fprintf(stderr, "pcap_open_live() failed with error code %d.\nerror message: %s.\n", errno, err);
            exit(EXIT_FAILURE);
        }

        // apllying sniffing filter
        filter = "icmp";
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

        return 0;
    }
