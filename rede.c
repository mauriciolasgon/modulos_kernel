#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP   "93.184.216.34"  // exemplo.com
#define SERVER_PORT 80
#define MESSAGE     "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
#define ITERATIONS  100

int main(void) {
    int sockfd, i;
    struct sockaddr_in servaddr;
    char buffer[1024];

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &servaddr.sin_addr) <= 0) {
        perror("inet_pton falhou");
        return EXIT_FAILURE;
    }

    for (i = 0; i < ITERATIONS; i++) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket");
            return EXIT_FAILURE;
        }
        if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
            perror("connect");
            close(sockfd);
            return EXIT_FAILURE;
        }
        send(sockfd, MESSAGE, strlen(MESSAGE), 0);
        recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        close(sockfd);
        usleep(50000);  // aguarda 50 ms antes de nova iteração
    }
    return EXIT_SUCCESS;
}
