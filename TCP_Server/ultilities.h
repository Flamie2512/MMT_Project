#ifndef TCP_SERVER_ULTILITIES_H
#define TCP_SERVER_ULTILITIES_H

#include <stddef.h>
#include "../entity/entities.h"

#define MAX_USER 3000
#define MAX_SESSION 3000
#define MAX_FAVS 128
#define MAX_FRIENDS 128
#define MAX_REQUESTS 128
#define MAX_NOTIFS 128

int init_data_store(const char *db_path);
void shutdown_data_store(void);

int send_request(int sockfd, const char *buf);
int recv_response(int sockfd, char *buff, size_t size);

int get_accounts(Account accounts[], int max_users, int *out_count);
Account *find_account(const char *username);
int create_account(const char *username, const char *password);

int get_user_favorites(const char *username, FavoritePlace favs[], int max, int *out_count);
int get_user_friends(const char *username, FriendRel frs[], int max, int *out_count);
int get_user_requests(const char *username, FriendRequest reqs[], int max, int *out_count);
int get_user_notifications(const char *username, Notification notifs[], int max, int *out_count);

int create_favorite(const char *owner, const char *name, const char *category, const char *location);
int update_favorite(int fav_id, const char *owner, const char *name, const char *category, const char *location);
int create_friend_request(const char *from, const char *to);
int get_friend_request_by_id(int request_id, FriendRequest *out_request);
int accept_friend_request(int request_id, const char *requestee);
int mark_notification_seen(int notif_id);

#endif /* TCP_SERVER_ULTILITIES_H */
