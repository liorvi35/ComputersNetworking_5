#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include<errno.h>


unsigned short checksum(void *b, int len)
{	
    unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result = 0;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

void send_raw_ip_packet(struct iphdr* ip)
{
    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock <= 0)
    {
        perror("socket() failed");
        exit(1);
    }

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)))
    {
        perror("setsockopt() failed");
        close(sock);
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->daddr;

    size_t s = sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr*)&addr, sizeof(addr));

    if(s < 0)
    {
        perror("sendto() failed");
        close(sock);
        exit(1);
    } 
    else if(s == 0)
    {
        fprintf(stderr, "send 0 bytes!\n");
        close(sock);
        exit(1);
    }

    close(sock);
}

int main(int agrc, char *argv[])
{
    char buffer[IP_MAXPACKET] = {'\0'};

    struct icmphdr *icmp = (struct icmphdr*)(buffer + sizeof(struct iphdr));
    icmp->type = 8;
    icmp->checksum = 0;
    icmp->checksum = checksum((unsigned short*)icmp, sizeof(struct icmphdr));


    struct iphdr *ip = (struct iphdr*)buffer;
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 20;
    ip->saddr = inet_addr("1.2.3.4");
    ip->daddr = inet_addr("10.0.2.15");
    ip->protocol = IPPROTO_ICMP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

    send_raw_ip_packet(ip);

    exit(0);
}

#include <netinet/ip_icmp.h>
#include <time.h>
#include<errno.h>


unsigned short checksum(void *b, int len)
{	
    unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result = 0;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

void send_raw_ip_packet(struct iphdr* ip)
{
    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock <= 0)
    {
        perror("socket() failed");
        exit(1);
    }

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)))
    {
        perror("setsockopt() failed");
        close(sock);
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->daddr;

    size_t s = sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr*)&addr, sizeof(addr));

    if(s < 0)
    {
        perror("sendto() failed");
        close(sock);
        exit(1);
    } 
    else if(s == 0)
    {
        fprintf(stderr, "send 0 bytes!\n");
        close(sock);
        exit(1);
    }

    close(sock);
}

int main(int agrc, char *argv[])
{
    char buffer[IP_MAXPACKET] = {'\0'};

    struct icmphdr *icmp = (struct icmphdr*)(buffer + sizeof(struct iphdr));
    icmp->type = 8;
    icmp->checksum = 0;
    icmp->checksum = checksum((unsigned short*)icmp, sizeof(struct icmphdr));


    struct iphdr *ip = (struct iphdr*)buffer;
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 20;
    ip->saddr = inet_addr("1.2.3.4");
    ip->daddr = inet_addr("10.0.2.15");
    ip->protocol = IPPROTO_ICMP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

    send_raw_ip_packet(ip);

    exit(0);
}
