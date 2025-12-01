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
#include <netinet/tcp.h>  // thêm ở đầu file
#include <pthread.h>


#define BUFF_SIZE 4096
#define BACKLOG 2
#define MAX_USER 3000
#define MAX_LEN 300
#define MAX_SESSION 3000

/**
 * @typedef account_t: Represents a user account.
 * Fields:
 *  - username: The username of the account.
 *  - status: The status of the account (1 = active, 0 = locked/disabled).
 */
typedef struct account_t {
    char username[MAX_LEN];
    int status; // 1 = active, 0 = locked/disabled
} Account;
static Account accounts[MAX_USER];
static int accountCount = 0;


/**
 * @typedef client_session_t: Represents a client session stored on server side.
 * Fields:
 *  - sockfd: socket descriptor for the client connection
 *  - client_addr: client's network address (sockaddr_in)
 *  - username: logged-in account name (empty if not logged in)
 *  - logged_in: 1 if user is logged in, 0 otherwise
 */
typedef struct client_session {
    int sockfd;
    struct sockaddr_in client_addr;
    char username[MAX_LEN];
    int logged_in; 
    char message[BUFF_SIZE * 4];
} client_session_t;

static client_session_t sessions[MAX_SESSION];


/**
 * @function send_request: Send a message to the client over the socket.
 *
 * @param sockfd: The file descriptor of the socket connected to the client.
 * @param buf: The message to be sent.
 *
 * @return The number of bytes sent, or -1 if an error occurred.
 */
int send_request(int sockfd, const char *buf) {
    ssize_t s = send(sockfd, buf, strlen(buf), 0);
    if (s == -1) {
        perror("send() error");
    }
    usleep(2000); 
    return s;
}


/**
 * @function recv_response: Receive a message from the client over the socket.
 *
 * @param sockfd: The file descriptor of the socket connected to the client.
 * @param buff: The buffer to store the received message.
 * @param size: The size of the buffer.
 *
 * @return The number of bytes received, or -1 if an error occurred, or 0 if the connection is closed.
 */
int recv_response(int sockfd, char *buff, size_t size) {
    ssize_t r = recv(sockfd, buff, size - 1, 0);
    if (r <= 0) {
        if (r < 0) perror("recv() error");
        return (int)r;
    }
    buff[r] = '\0';
    return (int)r;
}

/**
 * @function loadAccounts
 * Load account information from a text file.
 *
 * @param accounts : An array of Account structures to store loaded accounts.
 * @param filename : The name of the file containing account data.
 *
 * @return Number of accounts successfully loaded.
 *         0 if the file cannot be opened or is empty.
 */
void loadAccounts() {
    accountCount = 0;
    FILE *f = fopen("account.txt", "r");
    if (!f) {
        return;
    }
    while (accountCount < MAX_USER &&
           fscanf(f, "%s %d", accounts[accountCount].username, &accounts[accountCount].status) == 2) {
        accountCount++;
    }

    
    fclose(f);
}

/**
 * @function find_account: Find an account by username.
 *
 * @param name: The username to search for.
 *
 * @return Pointer to the Account structure if found, NULL otherwise.
 */
Account *find_account(const char *name) {
    for (int i = 0; i < accountCount; i++) {
        if (strcmp(name, accounts[i].username) == 0) {
            return &accounts[i];
        }
    }
    return NULL;
}

/**
 *@function process_line: Process a single command line from the client.
 *
 * @param session: Pointer to client_session_t structure containing client session info.
 * @param line: The command line to process.
 * 
 * @return NULL
 */
void process_line(client_session_t *session, const char *line) {
    printf("Handle command: '%s'\n", line);

    if (strncmp(line, "USER ", 5) == 0) {
        if (session->logged_in) {
            send_request(session->sockfd, "213 Already logged in\r\n");
        } else {
            sscanf(line + 5, "%s", session->username);
            Account *acc = find_account(session->username);
            if (acc == NULL) {
                send_request(session->sockfd, "212 Account not found\r\n");
            } else if (acc->status == 0) {
                send_request(session->sockfd, "211 Account locked\r\n");
            } else {
                session->logged_in = 1;
                send_request(session->sockfd, "110 Login successful\r\n");
            }
        }
    }
    else if (strncmp(line, "POST ", 5) == 0) {
        if (!session->logged_in) {
            send_request(session->sockfd, "221 Not logged in\r\n");
        } else {
            send_request(session->sockfd, "120 Post received\r\n");
        }
    }
    else if (strncmp(line, "BYE", 3) == 0) {
        if (!session->logged_in) {
            send_request(session->sockfd, "221 Not logged in\r\n");
        } else {
            session->logged_in = 0;
            printf("Log out from user %s\n", session->username);
            send_request(session->sockfd, "130 Logged out\r\n");
        }
    }
    else {
        send_request(session->sockfd, "300 Unknown request\r\n");
    }
}

/**
 * @function handle_client: Handle communication with a connected client.
 *
 * @param arg: Pointer to client_session_t structure containing client session info.
 *
 * @return NULL
 */
void handle_client(client_session_t *session, fd_set *allset) {
    char buff[BUFF_SIZE];
    int len;

    memset(buff, 0, sizeof(buff));
    if ((len = recv_response(session->sockfd, buff, sizeof(buff) - 1)) <= 0) {
        if (len == -1) perror("recv() error");
        printf("Client %d disconnected\n", session->sockfd);
        close(session->sockfd);   
        FD_CLR(session->sockfd, allset);
        session->sockfd = -1;
        session->logged_in = 0;
        session->message[0] = '\0';
        session->username[0] = '\0';
        return;
    }

    buff[len] = '\0';
    printf("\nRaw recv from client %d: '%s'\n", session->sockfd, buff);
       
    strcat(session->message, buff);

    if (strstr(session->message, "\r\n") == NULL) return;

    char *line = strtok(session->message, "\r\n");
    while (line != NULL) {
        process_line(session, line);
        line = strtok(NULL, "\r\n");
    }    
    
    session->message[0] = '\0';
}






int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <Port_Number>\n", argv[0]);
        return 1;
    }

    char *port = argv[1];

    loadAccounts();
    int listenfd, connfd,i,maxfd,sockfd,maxi, nready;
    fd_set readfds, allset;
    socklen_t clilen;
    struct sockaddr_in serverAddr, clientAddr;

    if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("Error: ");
        return 0;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(atoi(port));

    if(bind(listenfd, (struct sockaddr *) &serverAddr,sizeof(serverAddr) ) == -1){
        perror("Error: ");
        return 0;
    }

    if(listen(listenfd, BACKLOG) == -1){
        perror("listen() error.");
        return 0;
    }
    printf("Server started at port %s\n", port);

    maxfd = listenfd;
    maxi = -1;
    for (i = 0; i < FD_SETSIZE; i++) {
        sessions[i].sockfd = -1;
        sessions[i].logged_in = 0;
        sessions[i].message[0] = '\0';
        sessions[i].username[0] = '\0';
    }
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);
   
    while(1){     
        readfds = allset;
        nready = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (nready < 0) {
            if (errno == EINTR)
                continue;
            else {
                perror("select() error");
                exit(EXIT_FAILURE);
            }
        } 
        
        if(FD_ISSET(listenfd, &readfds)) {
            clilen = sizeof(clientAddr);

            if ((connfd = accept(listenfd, (struct sockaddr *) &clientAddr, &clilen)) < 0) {
                if (errno == EINTR)
                    continue;
                else {
                    perror("accept() error");
                    exit(EXIT_FAILURE);
                }
            } else {
                int flag = 1;
                setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
                for (i = 0; i < FD_SETSIZE; i++) {
                    if (sessions[i].sockfd < 0) {
                        sessions[i].sockfd = connfd;
                        sessions[i].client_addr = clientAddr;
                        sessions[i].logged_in = 0;
                        sessions[i].message[0] = '\0';
                        sessions[i].username[0] = '\0'; 
                        send_request(sessions[i].sockfd, "100 Welcome to the server\r\n");
                        break;
                    }
                }
                if (i == FD_SETSIZE) {
                    printf("Too many clients\n");
                    close(connfd);
                } else {
                    FD_SET(connfd, &allset);
                    if (connfd > maxfd) maxfd = connfd;
                    if (i > maxi) maxi = i;
                    printf("You got a connection from %s:%d (slot %d)\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), i);

                }

                if(--nready <= 0)
                    continue;
            }

        }

    for(i = 0; i <= maxi; i++) {
            sockfd = sessions[i].sockfd;
            if (sockfd < 0) continue;

            if (FD_ISSET(sockfd, &readfds)) {
                client_session_t *session = &sessions[i];
                
                handle_client(session, &allset);
                if (--nready <= 0)
                    break;
            }
        }
    }
    close(listenfd);
    return 0;

}
