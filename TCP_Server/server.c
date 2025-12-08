#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <strings.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include "ultilities.h"
#include "command_handlers.h"

#define BUFF_SIZE 4096
#define BACKLOG 2
#define MAX_FAVS 128
#define MAX_FRIENDS 128
#define MAX_REQUESTS 128
#define MAX_NOTIFS 128

pthread_mutex_t account_lock = PTHREAD_MUTEX_INITIALIZER;




/**
 * @function handle_client: Handle communication with a connected client.
 *
 * @param arg: Pointer to client_session_t structure containing client session info.
 *
 * @return NULL
 */
void *handle_client(void *arg) {
    char buff[BUFF_SIZE];
    char *message = malloc(BUFF_SIZE * 4);

    client_session_t *session = (client_session_t *)arg;
    message[0] = '\0';
    
    pthread_detach(pthread_self());
    
    send_request(session->sockfd, "100 Welcome to the server\r\n");

    while (1) {
        memset(buff, 0, sizeof(buff));
        int len = recv_response(session->sockfd, buff, sizeof(buff));
        if (len <= 0) break;

        buff[len] = '\0';
        printf("\n Raw recv: '%s'\n", buff);

        strcat(message, buff);

        if (strstr(message, "\r\n") == NULL) continue;
        char *line = strtok(message, "\r\n");
        while (line != NULL) {
            printf("Handle command: '%s'\n", line);
            dispatch_command(session, line);
            line = strtok(NULL, "\r\n");
        }
        message[0] = '\0';
    }

    free(message);
    close(session->sockfd);
    free(session);
    return NULL;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <Port_Number>\n", argv[0]);
        return 1;
    }

    char *port = argv[1];

    if (init_data_store(NULL) != 0) {
        fprintf(stderr, "Failed to initialize data store.\n");
        return 1;
    }

    int listenfd, connfd;
    struct sockaddr_in serverAddr, clientAddr;

    if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("Error: ");
        shutdown_data_store();
        return 0;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(atoi(port));

    if(bind(listenfd, (struct sockaddr *) &serverAddr,sizeof(serverAddr) ) == -1){
        perror("Error: ");
        shutdown_data_store();
        return 0;
    }

    if(listen(listenfd, BACKLOG) == -1){
        perror("listen() error.");
        shutdown_data_store();
        return 0;
    }
    printf("Server started at port %s\n", port);
   
    while(1){                
        connfd = (int *)malloc(sizeof(int));
        if (!connfd) {
            perror("malloc");
            continue;
        }
        socklen_t clientAddrLen = sizeof(clientAddr);

        if((connfd = accept(listenfd, (struct sockaddr *) &clientAddr, &clientAddrLen)) == -1){
            if (errno == EINTR) 
                continue;
            else {
                perror("accept");
                exit(EXIT_FAILURE);
            }
        } else {
            int flag = 1;
            setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
            char client_ip[INET_ADDRSTRLEN];
            if(inet_ntop(AF_INET, &(clientAddr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL) {
                perror("inet_ntop() error");
            }
            else{
                int client_port = ntohs(clientAddr.sin_port);
                printf("Client got a connection from %s:%d\n", client_ip, client_port);
            }

            client_session_t *session = malloc(sizeof(client_session_t));
            if (!session) {
                perror("malloc");
                close(connfd);
                continue;
            }
            session->sockfd = connfd;
            session->logged_in = 0;
            memcpy(&session->client_addr, &clientAddr, sizeof(clientAddr));
            session->username[0] = '\0';

            pthread_t tid;
            if (pthread_create(&tid, NULL, handle_client, (void *)session) != 0) {
                perror("pthread_create");
                close(connfd);
                free(session);
                continue;
            }
        }

    }
    close(listenfd);
    shutdown_data_store();
    return 0;

}
