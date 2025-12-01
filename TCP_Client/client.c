#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>

#define BUFF_SIZE 4096
#define MAX 3000

/**
 * @function send_request: Send a message to the server.
 *
 * @param sock: The socket file descriptor.
 * @param buf: The message to send.
 */
void send_request(int sock, const char *buf) {
    ssize_t s = send(sock, buf, strlen(buf), 0);
    if (s == -1) {
        perror("send() error");
    }
}

/**
 * @function recv_response: Receive a message from the server.
 *
 * @param sock: The socket file descriptor.
 * @param buff: The buffer to store the received message.
 * @param size: The size of the buffer.
 *
 * @return The number of bytes received, or -1 if an error occurred, or 0 if the connection is closed.
 */
int recv_response(int sock, char *buff, size_t size) {
    ssize_t rcv = recv(sock, buff, size - 1, 0);
    if (rcv <= 0) {
        if (rcv == -1) perror("recv() error");
        return (int)rcv;
    }
    buff[rcv] = '\0';
    return (int)rcv;
}

/**
 * @function menu: Display the command menu for the client.
 *
 * This function prints the list of available commands to the console.
 */
void menu(){
    printf("\n==============================\n");
    printf("     TCP CLIENT INTERFACE\n");
    printf("==============================\n");
    printf("Available commands:\n");
    printf("REGISTER <username> <password> : Register a new account\n");
    printf("USER <username> : This command is used to login.\n");
    printf("POST <message> : This command is used to send a message.\n");
    printf("BYE : This command is used to disconnect.\n");
    printf("------------------------------\n");
}



int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <domain_or_ip> <port>\n", argv[0]);
        return 1;
    }

    char *ip = argv[1];
    char *port = argv[2];

    int clientfd;
    struct sockaddr_in serverAddr;
    char buff[BUFF_SIZE+1];

    if((clientfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("Error: ");
        return 0;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(ip);
    serverAddr.sin_port = htons(atoi(port));

    if(connect(clientfd, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) == -1){
        perror("connect() error.");
        return 0;
    }

    memset(buff, 0, BUFF_SIZE);
    int rcvBytes = recv(clientfd, buff, BUFF_SIZE, 0);
    if (rcvBytes <= 0) {
        printf("Failed to receive welcome message\n");
        close(clientfd);
        return 1;
    }
    buff[rcvBytes] = '\0';
    printf("%s", buff);

    char *message = malloc(BUFF_SIZE * 4);
    if (!message) {
        perror("malloc() error");
        close(clientfd);
        return 1;
    }
    message[0] = '\0';

    while (1) {
        menu();
        printf("Enter command: ");
        fgets(buff, MAX, stdin);
        buff[strcspn(buff, "\n")] = '\0';

        if (strlen(buff) == 0) continue;

        strcat(buff, "\r\n");
        send_request(clientfd, buff);
            
        
        memset(buff, 0, sizeof(buff));
        rcvBytes = recv_response(clientfd, buff, sizeof(buff));
        if (rcvBytes <= 0) break;
        buff[rcvBytes] = '\0';
        strcat(message, buff);
        if (strstr(message, "\r\n") == NULL) continue;
        char *line = strtok(message, "\r\n");
        while (line != NULL) {
            printf("------------------------------\n");
            printf("Server: %s\n", line);
            fflush(stdout);
            line = strtok(NULL, "\r\n");
        }
        message[0] = '\0';
    
    }

    close(clientfd);
    return 0;
}
