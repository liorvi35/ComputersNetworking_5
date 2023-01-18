#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>


#define PORT 9090
#define MAX_LEN 1024

void Send_data(int sockfd, struct sockaddr_in cliaddr, socklen_t len)
{
    ssize_t n;
    float rnd;

    rnd = ((float)random()) / ((float)RAND_MAX);
    printf("Random number: %f\n", rnd);

    if (rnd > 0.5)
    {
        // Send data to the socket
        char *msg = "Hello!";
        n = sendto(sockfd, msg, strlen(msg) + 1 , 0, (struct sockaddr *)&cliaddr, len);
        if (n < 0)
        {
            perror("Error sending data");
            close(sockfd);
        }
        else
        {
            printf("send...\n");
        }
    }
}

int main(int argc, char *argv[])
{

    if (argc != 2) // checking that the user has specified an IP address 
    {
        printf("usage: ./Gateway <ip>\n");
        exit(EXIT_FAILURE);
    }

    int sockfd;
    char buffer[MAX_LEN];
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len;
    ssize_t n;

    // Create the socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Error creating socket");
        exit(errno);
    }

    // Bind the socket to a specific port
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("Error binding socket");
        close(sockfd);
        exit(errno);
    }

    printf("wait for upd packet...\n");

    // Receive data from the socket
    
    len = sizeof(cliaddr);
    while (1)
    {
        n = recvfrom(sockfd, buffer, MAX_LEN, 0, (struct sockaddr *)&cliaddr, &len);
        if (n < 0)
        {
            perror("Error receiving data");
            close(sockfd);
            exit(errno);
        }
        else
        {
            buffer[n] = '\0';
            printf("Received %ld bytes from %s:%d\n", n, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));
            if(inet_aton(argv[1], &cliaddr.sin_addr) < 0)
            {
                perror("inet_aton() failed");
                close(sockfd);
                exit(errno);
            }
            cliaddr.sin_port = htons(PORT + 1);
            Send_data(sockfd , cliaddr ,len);
            cliaddr.sin_port = htons(PORT);
        }
    }

    // Close the socket
    close(sockfd);
    return 0;
}
