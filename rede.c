#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP     "127.0.0.1"
#define SERVER_PORT   8000
#define REQUEST       "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
#define ITERATIONS    100

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
        if (send(sockfd, REQUEST, strlen(REQUEST), 0) < 0) {
            perror("send");
            close(sockfd);
            return EXIT_FAILURE;
        }
        int n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            printf("Resposta %d:\n%s\n", i+1, buffer);
        }
        close(sockfd);
        usleep(50000);  // 50 ms
    }
    return EXIT_SUCCESS;
}
