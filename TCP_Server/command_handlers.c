#include "command_handlers.h"
#include "ultilities.h"

#include <stdio.h>
#include <string.h>

static void handle_login(client_session_t *session, const char *payload);
static void handle_logout(client_session_t *session);
static void handle_register(client_session_t *session, const char *payload);
static void handle_add_favorite(client_session_t *session, const char *payload);
static void handle_add_friend(client_session_t *session, const char *payload);
static void handle_accept_friend(client_session_t *session, const char *payload);
static void handle_list_favorites(client_session_t *session, const char *payload);
static void handle_edit_favorite(client_session_t *session, const char *payload);
static void handle_not_implemented(client_session_t *session);

static void send_bad_request(client_session_t *session, const char *message) {
    char buff[128];
    snprintf(buff, sizeof(buff), "400 %s\r\n", message ? message : "Bad request");
    send_request(session->sockfd, buff);
}

void dispatch_command(client_session_t *session, const char *command) {
    if (!session || !command) {
        return;
    }
    if (strncmp(command, "LOGIN|", 6) == 0) {
        handle_login(session, command + 6);
    } else if (strcmp(command, "LOGOUT") == 0 || strcmp(command, "LOGOUT|") == 0) {
        handle_logout(session);
    } else if (strncmp(command, "REGISTER|", 9) == 0) {
        handle_register(session, command + 9);
    } else if (strncmp(command, "ADD_FAVORITE|", 13) == 0){
        handle_add_favorite(session, command + 13);
    } else if (strncmp(command, "LIST_FAVORITES", 14) == 0) {
        handle_list_favorites(session, command + 14);
    } else if (strncmp(command, "DEL_FAVORITE|", 12) == 0) {
        handle_not_implemented(session);
    }
    else if ( strncmp(command, "SHARE_FAVORITE|", 15) == 0 ){
        handle_not_implemented(session);
        
    } else if (strncmp(command, "EDIT_FAVORITE|", 13) == 0 ){
        handle_edit_favorite(session, command + 13);
    } else if (strncmp(command, "ADD_FRIEND|", 11) == 0 ){
        handle_add_friend(session, command + 11);
    } else if (strncmp(command, "LIST_FRIENDS", 12) == 0 ){
        handle_not_implemented(session);
    } else if (strncmp(command, "ACCEPT_FRIEND|", 14) == 0 ){
        handle_accept_friend(session, command + 14);
    } else if (strncmp(command, "LIST_REQUESTS", 13) == 0 ){
        handle_not_implemented(session);
    } else if (strncmp(command, "REJECT_FRIEND|", 14) == 0 ){
        handle_not_implemented(session);
    } else if (strncmp(command, "REMOVE_FRIEND|", 14) == 0 ){
        handle_not_implemented(session);
    } else if (strncmp(command, "TAG_FRIEND|", 10) == 0 ){
        handle_not_implemented(session);
    } else if (strncmp(command, "LIST_NOTIFICATIONS", 19) == 0){
        handle_not_implemented(session);
    } else {
        send_bad_request(session, "Unknown command");
    }
    
}

static void handle_login(client_session_t *session, const char *payload) {
    char username[MAX_NAME_LEN];
    char password[MAX_PASS_LEN];

    if (!payload || sscanf(payload, "%63[^|]|%127[^\r\n]", username, password) != 2) {
        send_bad_request(session, "Invalid LOGIN format");
        return;
    }

    Account *acc = find_account(username);
    if (!acc) {
        send_request(session->sockfd, "401 Invalid username or password\r\n");
        return;
    }

    if (acc->is_logged_in) {
        send_request(session->sockfd, "402 Account already logged in\r\n");
        return;
    }

    if (strcmp(acc->password, password) != 0) {
        send_request(session->sockfd, "401 Invalid username or password\r\n");
        return;
    }

    acc->is_logged_in = 1;
    session->logged_in = 1;
    strncpy(session->username, username, sizeof(session->username) - 1);
    session->username[sizeof(session->username) - 1] = '\0';

    send_request(session->sockfd, "200 Login successful\r\n");
}

static void handle_logout(client_session_t *session) {
    if (!session->logged_in) {
        send_request(session->sockfd, "405 Not logged in\r\n");
        return;
    }

    Account *acc = find_account(session->username);
    if (acc) {
        acc->is_logged_in = 0;
    }

    session->logged_in = 0;
    session->username[0] = '\0';

    send_request(session->sockfd, "200 Logout successful\r\n");
}

static void handle_register(client_session_t *session, const char *payload) {
    char username[MAX_NAME_LEN];
    char password[MAX_PASS_LEN];
    if(session->logged_in){
        send_request(session->sockfd, "406 Already logged in\r\n");
        return;
    }

    if (!payload || sscanf(payload, "%63[^|]|%127[^\r\n]", username, password) != 2) {
        send_bad_request(session, "Invalid REGISTER format");
        return;
    }

    int result = create_account(username, password);
    if (result == 0) {
        send_request(session->sockfd, "200 Register successful\r\n");
    } else if (result == -2) {
        send_request(session->sockfd, "404 Username already exists\r\n");
    } else if (result == -1) {
        send_request(session->sockfd, "500 Server full, cannot register\r\n");
    } else {
        send_request(session->sockfd, "500 Internal server error\r\n");
    }
}


static void handle_add_favorite(client_session_t *session, const char *payload) {
    if (!session->logged_in) {
        send_request(session->sockfd, "405 Not logged in\r\n");
        return;
    }

    char name[MAX_TITLE_LEN];
    char category[MAX_CAT_LEN];
    char location[MAX_DESC_LEN];

    if (!payload || sscanf(payload, "%127[^|]|%63[^|]|%255[^\r\n]", name, category, location) != 3) {
        send_bad_request(session, "Invalid ADD_FAVORITE format");
        return;
    }

    int fav_id = create_favorite(session->username, name, category, location);
    if (fav_id < 0) {
        send_request(session->sockfd, "501 Failed to add favorite\r\n");
        return;
    }

    char response[128];
    snprintf(response, sizeof(response), "200 Add favorite successful: %d\r\n", fav_id);
    send_request(session->sockfd, response);
}

static void handle_add_friend(client_session_t *session, const char *payload) {
    if (!session->logged_in) {
        send_request(session->sockfd, "405 Not logged in\r\n");
        return;
    }

    char target[MAX_NAME_LEN];
    if (!payload || sscanf(payload, "%63[^\r\n]", target) != 1) {
        send_bad_request(session, "Invalid ADD_FRIEND format");
        return;
    }

    if (strcmp(target, session->username) == 0) {
        send_bad_request(session, "Cannot friend yourself");
        return;
    }

    Account *target_acc = find_account(target);
    if (!target_acc) {
        send_request(session->sockfd, "404 User not found\r\n");
        return;
    }

    FriendRel friends[MAX_FRIENDS];
    int friend_count = 0;
    if (get_user_friends(session->username, friends, MAX_FRIENDS, &friend_count) != 0) {
        send_request(session->sockfd, "500 Failed to check friendships\r\n");
        return;
    }

    for (int i = 0; i < friend_count; ++i) {
        const char *a = friends[i].user_a;
        const char *b = friends[i].user_b;
        if ((strcmp(a, session->username) == 0 && strcmp(b, target) == 0) ||
            (strcmp(a, target) == 0 && strcmp(b, session->username) == 0)) {
            send_request(session->sockfd, "407 Already friends\r\n");
            return;
        }
    }

    FriendRequest requests[MAX_REQUESTS];
    int req_count = 0;
    if (get_user_requests(session->username, requests, MAX_REQUESTS, &req_count) != 0) {
        send_request(session->sockfd, "500 Failed to check friend requests\r\n");
        return;
    }

    for (int i = 0; i < req_count; ++i) {
        if (strcmp(requests[i].to, target) == 0 && requests[i].status == 0) {
            send_request(session->sockfd, "410 Friend request already sent\r\n");
            return;
        }
    }

    int rc = create_friend_request(session->username, target);
    if (rc == -2) {
        send_request(session->sockfd, "410 Friend request already sent\r\n");
        return;
    }
    if (rc != 0) {
        send_request(session->sockfd, "500 Failed to create friend request\r\n");
        return;
    }

    send_request(session->sockfd, "200 Friend request sent\r\n");
}

static void handle_list_favorites(client_session_t *session, const char *payload) {
    if (!session->logged_in) {
        send_request(session->sockfd, "405 Not logged in\r\n");
        return;
    }

    if (payload && payload[0] != '\0') {
        const char *extra = payload;
        if (extra[0] == '|') extra++;
        while (*extra == ' ') extra++;
        if (*extra != '\0') {
            send_bad_request(session, "Invalid LIST_FAVORITES format");
            return;
        }
    }

    FavoritePlace favorites[MAX_FAVS];
    int fav_count = 0;
    if (get_user_favorites(session->username, favorites, MAX_FAVS, &fav_count) != 0) {
        send_request(session->sockfd, "500 Failed to fetch favorites\r\n");
        return;
    }

    char header[64];
    snprintf(header, sizeof(header), "200 Favorites %d\r\n", fav_count);
    send_request(session->sockfd, header);

    for (int i = 0; i < fav_count; ++i) {
        char line[768];
        snprintf(line, sizeof(line),
                 "210 %d|%s|%s|%s|%d|%s|%s|%lld\r\n",
                 favorites[i].id,
                 favorites[i].name,
                 favorites[i].category,
                 favorites[i].location,
                 favorites[i].is_shared,
                 favorites[i].sharer,
                 favorites[i].tagged,
                 (long long)favorites[i].created_at);
        send_request(session->sockfd, line);
    }
}


static void handle_accept_friend(client_session_t *session, const char *payload) {
    if (!session->logged_in) {
        send_request(session->sockfd, "405 Not logged in\r\n");
        return;
    }

    int request_id = 0;
    if (!payload || sscanf(payload, "%d", &request_id) != 1 || request_id <= 0) {
        send_bad_request(session, "Invalid ACCEPT_FRIEND format");
        return;
    }

    FriendRequest request;
    memset(&request, 0, sizeof(request));
    int rc = get_friend_request_by_id(request_id, &request);
    if (rc == -2) {
        send_request(session->sockfd, "404 Friend request not found\r\n");
        return;
    }
    if (rc != 0) {
        send_request(session->sockfd, "500 Failed to load friend request\r\n");
        return;
    }

    if (strcmp(request.to, session->username) != 0) {
        send_request(session->sockfd, "403 Friend request not addressed to you\r\n");
        return;
    }

    if (request.status != 0) {
        send_request(session->sockfd, "409 Friend request already processed\r\n");
        return;
    }

    rc = accept_friend_request(request_id, session->username);
    if (rc == -2) {
        send_request(session->sockfd, "404 Friend request not found\r\n");
        return;
    }
    if (rc == -3) {
        send_request(session->sockfd, "409 Friend request already processed\r\n");
        return;
    }
    if (rc == -4) {
        send_request(session->sockfd, "403 Friend request not addressed to you\r\n");
        return;
    }
    if (rc != 0) {
        send_request(session->sockfd, "500 Failed to accept friend request\r\n");
        return;
    }

    char response[128];
    snprintf(response, sizeof(response), "200 Friend request accepted %s\r\n", request.from);
    send_request(session->sockfd, response);
}


static void handle_not_implemented(client_session_t *session) {
    send_request(session->sockfd, "501 Not implemented\r\n");
}
