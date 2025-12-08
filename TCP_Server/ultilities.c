#include "ultilities.h"
#include "database.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

extern Account accounts[];
extern int accountCount;
extern pthread_mutex_t account_lock;

static int copy_accounts_from_db(Account accounts[], int max_users, int *out_count) {
	int fetched = 0;
	int rc = db_fetch_accounts(accounts, max_users, &fetched);
	if (rc != 0) return rc;
	if (out_count) *out_count = fetched;
	for (int i = 0; i < fetched; ++i) {
		accounts[i].is_logged_in = 0;
	}
	return 0;
}

int init_data_store(const char *db_path) {
	const char *path = db_path ? db_path : "data/mmt.db";
	return db_initialize(path);
}

void shutdown_data_store(void) {
	db_shutdown();
}

int send_request(int sockfd, const char *buf) {
	if (!buf) {
		errno = EINVAL;
		return -1;
	}
	ssize_t s = send(sockfd, buf, strlen(buf), 0);
	if (s == -1) {
		perror("send() error");
		return -1;
	}
	usleep(2000);
	return (int)s;
}

int recv_response(int sockfd, char *buff, size_t size) {
	if (!buff || size == 0) {
		errno = EINVAL;
		return -1;
	}
	ssize_t r = recv(sockfd, buff, size - 1, 0);
	if (r <= 0) {
		if (r < 0) perror("recv() error");
		return (int)r;
	}
	buff[r] = '\0';
	return (int)r;
}

int get_accounts(Account accounts_buffer[], int max_users, int *out_count) {
	if (!accounts_buffer || !out_count || max_users <= 0) return -1;
	return copy_accounts_from_db(accounts_buffer, max_users, out_count);
}

Account *find_account(const char *username) {
	if (!username) return NULL;
	for (int i = 0; i < accountCount; ++i) {
		if (strcmp(accounts[i].username, username) == 0) {
			return &accounts[i];
		}
	}
	return NULL;
}

int create_account(const char *username, const char *password) {
	if (!username || !password) return -1;

	pthread_mutex_lock(&account_lock);

	if (find_account(username)) {
		pthread_mutex_unlock(&account_lock);
		return -2;
	}

	if (accountCount >= MAX_USER) {
		pthread_mutex_unlock(&account_lock);
		return -1;
	}

	int db_result = db_create_account(username, password);
	if (db_result != 0) {
		pthread_mutex_unlock(&account_lock);
		return db_result;
	}

	Account new_acc;
	memset(&new_acc, 0, sizeof(new_acc));
	strncpy(new_acc.username, username, sizeof(new_acc.username) - 1);
	strncpy(new_acc.password, password, sizeof(new_acc.password) - 1);
	new_acc.is_logged_in = 0;

	accounts[accountCount++] = new_acc;

	pthread_mutex_unlock(&account_lock);
	return 0;
}

int get_user_favorites(const char *username, FavoritePlace favs[], int max, int *out_count) {
	if (!username || !out_count || max <= 0) return -1;
	if (!favs) {
		*out_count = 0;
		return 0;
	}
	return db_fetch_user_favorites(username, favs, max, out_count);
}

int get_user_friends(const char *username, FriendRel frs[], int max, int *out_count) {
	if (!username || !out_count || max <= 0) return -1;
	if (!frs) {
		*out_count = 0;
		return 0;
	}
	return db_fetch_user_friends(username, frs, max, out_count);
}

int get_user_requests(const char *username, FriendRequest reqs[], int max, int *out_count) {
	if (!username || !out_count || max <= 0) return -1;
	if (!reqs) {
		*out_count = 0;
		return 0;
	}
	return db_fetch_user_requests(username, reqs, max, out_count);
}

int get_user_notifications(const char *username, Notification notifs[], int max, int *out_count) {
	if (!username || !out_count || max <= 0) return -1;
	if (!notifs) {
		*out_count = 0;
		return 0;
	}
	return db_fetch_user_notifications(username, notifs, max, out_count);
}

int create_favorite(const char *owner, const char *name, const char *category, const char *location) {
	if (!owner || !name || !category || !location) return -1;
	return db_create_favorite(owner, name, category, location);
}

int update_favorite(int fav_id, const char *owner, const char *name, const char *category, const char *location) {
	if (!owner || !name || !category || !location) return -1;
	return db_update_favorite(fav_id, owner, name, category, location);
}

int create_friend_request(const char *from, const char *to) {
	if (!from || !to) return -1;
	return db_create_friend_request(from, to);
}

int get_friend_request_by_id(int request_id, FriendRequest *out_request) {
	if (!out_request || request_id <= 0) return -1;
	return db_get_friend_request(request_id, out_request);
}

int accept_friend_request(int request_id, const char *requestee) {
	if (!requestee || request_id <= 0) return -1;
	return db_accept_friend_request(request_id, requestee);
}

int mark_notification_seen(int notif_id) {
	return db_mark_notification_seen(notif_id);
}

int add_favorite(const char *owner, const char *name, const char *category, const char *location) {
    if (!owner || !name || !category || !location) return 0;

    FavoritePlace f;
    memset(&f, 0, sizeof(f));
    f.id = get_next_fav_id();
    strncpy(f.owner, owner, sizeof(f.owner)-1); f.owner[sizeof(f.owner)-1] = '\0';
    strncpy(f.name, name, sizeof(f.name)-1); f.name[sizeof(f.name)-1] = '\0';
    strncpy(f.category, category, sizeof(f.category)-1); f.category[sizeof(f.category)-1] = '\0';
    strncpy(f.location, location, sizeof(f.location)-1); f.location[sizeof(f.location)-1] = '\0';
    f.is_shared = 0;
    f.sharer[0] = '\0';
    f.tagged[0] = '\0';
    f.created_at = time(NULL);

    FILE *fp = fopen(FAV_PATH, "a");
    if (!fp) {
        perror("add_favorite: fopen");
        return -1;
    }

    int data = fprintf(fp, "%d|%s|%s|%s|%s|%d|%s|%s|%ld\n",
                       f.id, f.owner, f.name, f.category, f.location,
                       f.is_shared,
                       f.sharer, f.tagged, (long)f.created_at);
    fclose(fp);
    if (data < 0) return -2;
    return f.id;
}