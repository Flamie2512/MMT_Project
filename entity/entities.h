#ifndef ENTITY_ENTITIES_H
#define ENTITY_ENTITIES_H

#include <time.h>

#define MAX_NAME_LEN 64
#define MAX_PASS_LEN 128
#define MAX_TITLE_LEN 128
#define MAX_CAT_LEN 64
#define MAX_DESC_LEN 256
#define MAX_TAGGED_LEN 256
#define MAX_MSG_LEN 256

typedef struct account_t {
    char username[MAX_NAME_LEN];
    char password[MAX_PASS_LEN]; 
    int is_logged_in; 
} Account;

typedef struct friend_request_t {
    int id;
    char from[MAX_NAME_LEN];
    char to[MAX_NAME_LEN];
    int status; 
    time_t created_at;
} FriendRequest;

typedef struct friend_rel_t {
    char user_a[MAX_NAME_LEN];
    char user_b[MAX_NAME_LEN];
    time_t since;
} FriendRel;

typedef struct favorite_place_t {
    int id;
    char name[MAX_TITLE_LEN];
    char category[MAX_CAT_LEN];
    char location[MAX_DESC_LEN];
    int is_shared;
    char sharer[MAX_NAME_LEN]; 
    char tagged[MAX_TAGGED_LEN]; 
    time_t created_at;
} FavoritePlace;

typedef struct notification_t {
    int id;
    char to[MAX_NAME_LEN];
    char from[MAX_NAME_LEN];
    int fav_id;
    char message[MAX_MSG_LEN];
    int seen; 
    time_t created_at;
} Notification;

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
    char username[MAX_NAME_LEN];
    int logged_in; 
} client_session_t;

#endif 
