#ifndef TCP_SERVER_DATABASE_H
#define TCP_SERVER_DATABASE_H

#include <time.h>
#include <stddef.h>

#include "../entity/entities.h"

int db_initialize(const char *db_path);
void db_shutdown(void);

int db_fetch_accounts(Account accounts[], int max_users, int *out_count);
int db_create_account(const char *username, const char *password);

int db_fetch_user_favorites(const char *owner, FavoritePlace favs[], int max_items, int *out_count);
int db_fetch_user_friends(const char *username, FriendRel friends[], int max_items, int *out_count);
int db_fetch_user_requests(const char *username, FriendRequest requests[], int max_items, int *out_count);
int db_fetch_user_notifications(const char *username, Notification notifications[], int max_items, int *out_count);

int db_create_favorite(const char *owner, const char *name, const char *category, const char *location);
int db_update_favorite(int fav_id, const char *owner, const char *name, const char *category, const char *location);
int db_create_friend_request(const char *from_user, const char *to_user);
int db_mark_notification_seen(int notif_id);
int db_get_friend_request(int request_id, FriendRequest *out_request);
int db_accept_friend_request(int request_id, const char *requestee);

#endif /* TCP_SERVER_DATABASE_H */
