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
#include "entity/entities.h"


// Utility function declarations
int send_request(int sockfd, const char *buf);
int recv_response(int sockfd, char *buff, size_t size);
int load_accounts_file(const char *path, Account accounts[], int max_users, int *out_count);
int load_user_favorites(const char *username, FavoritePlace favs[], int max, int *out_count);
int load_user_friends(const char *username, FriendRel frs[], int max, int *out_count);
int load_user_requests(const char *username, FriendRequest reqs[], int max, int *out_count);
int load_user_notifications(const char *username, Notification notifs[], int max, int *out_count);
int find_account(const char *username);
int mark_notification_seen(int notif_id);


//function 
void login(const char *username, const char *password);
void logout(const char *username);
int register_account(const char *username, const char *password) {
    // check username exists
    for (int i = 0; i < accountCount; i++) {
        if (strcmp(accounts[i].username, username) == 0) {
            return -2;
        }
    }

    // check server full
    if (accountCount >= MAX_USER) {
        return -1;
    }

    // Create new account
    Account new_acc;
    strncpy(new_acc.username, username, sizeof(new_acc.username) - 1);
    new_acc.username[sizeof(new_acc.username) - 1] = '\0';
    strncpy(new_acc.password, password, sizeof(new_acc.password) - 1);
    new_acc.password[sizeof(new_acc.password) - 1] = '\0';
    new_acc.status = 1;       // account active
    new_acc.is_logged_in = 0; // not logged in

    // Add to accounts array
    accounts[accountCount] = new_acc;
    accountCount++;

    // Write to account.txt
    char line[128];
    snprintf(line, sizeof(line), "%s|%s|1|", username, password);
    FILE *f = fopen("account.txt", "a");
    if (f) {
        fprintf(f, "%s\n", line);
        fclose(f);
    } else {
        perror("fopen account.txt");
    }
    return 0;
}

void add_favorite(const char *owner, const char *name, const char *category, const char *location, int is_shared, const char *sharer, const char *tagged);
void delete_favorite(const char *owner, int fav_id);
void edit_favorite(const char *owner, int fav_id, const char *name, const char *category, const char *location, int is_shared, const char *sharer, const char *tagged);
void share_favorite(const char *owner, int fav_id, const char *sharer, const char *tagged);
void add_friend_request(const char *from, const char *to);
void accept_friend_request(int req_id);
void reject_friend_request(int req_id);
void remove_friend(const char *user_a, const char *user_b);

#define BUFF_SIZE 4096
#define BACKLOG 2
#define MAX_USER 3000
#define MAX_SESSION 3000
static Account accounts[MAX_USER];
static int accountCount = 0;

/** Mutex for synchronizing access to account data */
pthread_mutex_t account_lock = PTHREAD_MUTEX_INITIALIZER;

void handle_command(client_session_t *session, const char *command){
    if (strncmp(line, "LOGIN|", 6) == 0) {
        if (sccanf(line + 6, "%63[^|]|%127[^\r\n]", username, password) != 2) {
            send_request(session->sockfd, "400 Invalid LOGIN format\r\n");
            return;
        }

        login(username, password, session);
        
    } else if(strncmp(line, "LOGOUT|", 7) == 0) {
        
    } else if (strncmp(line, "REGISTER|", 9) == 0) {
        if (sscanf(line + 9, "%63[^|]|%127[^\r\n]", username, password) != 2) {
            send_request(session->sockfd, "400 Invalid REGISTER format\r\n");
            return;
        }
        int reg_result = register_account(username, password);
        if (reg_result == 0) {
            send_request(session->sockfd, "201 Registration successful\r\n");
        } else if (reg_result == -2) {
            send_request(session->sockfd, "400 Username already exists\r\n");
        } else if (reg_result == -1) {
            send_request(session->sockfd, "500 Server full, cannot register\r\n");
        }
    } else if (strncmp(line, "ADD_FAVORITE|", 13) == 0) {
        
    } else if (strncmp(line, "LIST_FAVORITES|", 15) == 0) {
        
    } else if (strncmp(line, "DEL_FAVORITE|", 12) == 0) {
        
    } else if (strncmp(line, "SHARE_FAVORITE|", 15) == 0) {
    
    } else if( strncmp(line, "EDIT_FAVORITE|", 13) == 0) { 
    
    } else if (strncmp(line, "ADD_FRIEND|", 11) == 0) {
        
    } else if (strncmp(line, "LIST_FRIENDS|", 13) == 0) {
        
    } else if (strncmp(line, "ACCEPT_FRIEND|", 16) == 0) {
        
    } else if (strncmp(line, "LIST_REQUESTS|", 14) == 0) {
        
    } else if (strncmp(line, "REJECT_FRIEND|", 16) == 0) {
        
    } else if (strncmp(line, "REMOVE_FRIEND|", 15) == 0) {
        
    } else if (strncmp(line, "LIST_NOTIFICATIONS|", 18) == 0) {
        
    }else {
        send_request(session->sockfd, "400 Unknown request\r\n");
    }
};

void login(const char *username, const char *password, client_session_t *session) {
    Account *acc = find_account(username);
    if (!acc) send_request(session->sockfd, "401 Invalid username or password\r\n");
    if (acc->is_logged_in) {
        send_request(session->sockfd, "402 Account already logged in\r\n");
    }
    if (strcmp(acc->password, password) != 0) {
        send_request(session->sockfd, "401 Invalid username or password\r\n");
    } else {
        acc->is_logged_in = 1;
        session->logged_in = 1;
        strncpy(session->username, username, sizeof(session->username)-1);
        session->username[sizeof(session->username)-1] = '\0';
        send_request(session->sockfd, "200 Login successful\r\n");
    }
    
    return 0;
}

void logout(const char *username) {
    Account *acc = find_account(username);
    if (acc && acc->is_logged_in) {
        acc->is_logged_in = 0;
    }
    send_request(session->sockfd, "201 Logout successful\r\n");
}

void add_friend_request(const char *from, const char *to) {
    FriendRequest *reqs;
    int req_count = 0;
    if (load_user_requests(from, reqs, MAX_REQUESTS, &req_count) < 0) {
        send_request(session->sockfd, "500 Internal server error\r\n");
        return;
    }
    for (int i = 0; i < req_count; i++) {
        if (strcmp(reqs[i].to, to) == 0 && reqs[i].status == 0) {
            send_request(session->sockfd, "403 Friend request already sent\r\n");
            return;
        }
    }
    if(cretate_friend_request(from, to) < 0) {
        send_request(session->sockfd, "500 Internal server error\r\n");
        return;
    }
    send_request(session->sockfd, "202 Friend request sent\r\n");
}



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
    FavoritePlace user_favorites[MAX_FAVS];
    int favorites_count = 0;

    FriendRel user_friends[MAX_FRIENDS];
    int friends_count = 0;

    FriendRequest user_requests[MAX_REQUESTS];
    int requests_count = 0;

    Notification user_notifications[MAX_NOTIFS];
    int notifications_count = 0;
    
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
            handle_command(session, line);
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

    if (load_accounts_file("account.txt", accounts, MAX_USER, &accountCount) < 0) {
        accountCount = 0;
        printf("Warning: failed to load account list (account.txt)\n");
    }
    printf("Loaded %d accounts. Other data will be loaded per-user on login.\n", accountCount);
    int listenfd, connfd;
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
    return 0;

}
