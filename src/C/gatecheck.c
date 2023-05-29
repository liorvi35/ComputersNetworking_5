#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define PORT 9090
#define MAX_LEN 1024

int main()
{
    int sockfd;
    struct sockaddr_in servaddr;
    ssize_t n;
    char *message = "Hello, server!";

    // Create the socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Error creating socket");
        return 1;
    }

    // Set the server address and port
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    // Send data to the server
    n = sendto(sockfd, message, strlen(message) + 1, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (n < 0)
    {
        perror("Error sending data");
        close(sockfd);
        return 1;
    }

    // Close the socket
    close(sockfd);
    return 0;
}
