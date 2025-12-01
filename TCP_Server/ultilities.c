#include "../entity/entities.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

int send_request(int sockfd, const char *buf) {
    ssize_t s = send(sockfd, buf, strlen(buf), 0);
    if (s == -1) {
        perror("send() error");
        return -1;
    }
    usleep(2000);
    return (int)s;
}

int recv_response(int sockfd, char *buff, size_t size) {
    ssize_t r = recv(sockfd, buff, size - 1, 0);
    if (r <= 0) {
        if (r < 0) perror("recv() error");
        return (int)r;
    }
    buff[r] = '\0';
    return (int)r;
}


int get_next_id_from_file(const char *file_path) {
    if (!file_exists(file_path)) return 1;
    FILE *f = fopen(file_path, "r");
    if (!f) return 1;
    char line[1024];
    int max_id = 0;
    while (fgets(line, sizeof(line), f)) {
        int id = 0;
        if (sscanf(line, "%d|", &id) == 1) {
            if (id > max_id) max_id = id;
        }
    }
    fclose(f);
    return max_id + 1;
}

int append_line_to_file(const char *file_path, const char *line) {
    FILE *f = fopen(file_path, "a");
    if (!f) {
        perror(file_path);
        return -1;
    }
    fprintf(f, "%s\n", line);
    fclose(f);
    return 0;
}

int load_accounts_file(const char *path, Account accounts[], int max_users, int *out_count) {
    if (!path || !accounts || !out_count) return -1;
    *out_count = 0;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f) && *out_count < max_users) {
        if (line[0] == '#' || line[0] == '\n') continue;
        line[strcspn(line, "\r\n")] = '\0';
        Account tmp;
        char *tok, *saveptr = NULL;
        tok = strtok_r(line, "|", &saveptr); if (!tok) continue; tmp.username = tok;
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.password = tok;
        tmp.is_logged_in = 0;
        accounts[*out_count] = tmp;
        (*out_count)++;
    }
    fclose(f);
    return *out_count;
}


int load_user_favorites(const char *username, FavoritePlace favs[], int max, int *out_count) {
    if (!username || !favs || !out_count) return -1;
    *out_count = 0;
    FILE *f = fopen("data/favorites.txt", "r");
    if (!f) return -1;
    char line[1024];
    while (fgets(line, sizeof(line), f) && *out_count < max) {
        if (line[0] == '#' || line[0] == '\n') continue;
        line[strcspn(line, "\r\n")] = '\0';
        FavoritePlace tmp;
        char *tok, *saveptr = NULL;
        tok = strtok_r(line, "|", &saveptr); if (!tok) continue; tmp.id = atoi(tok);
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.owner = tok;
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.name = tok;
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.category = tok;
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.location = tok ;
        tok = strtok_r(NULL, "|", &saveptr); tmp.is_shared = tok ? atoi(tok) : 0;
        tok = strtok_r(NULL, "|", &saveptr); if (tok) tmp.sharer = tok; 
        tok = strtok_r(NULL, "|", &saveptr); if (tok) tmp.tagged = tok; 
        tok = strtok_r(NULL, "|", &saveptr); tmp.created_at = tok ? (time_t)atol(tok) : 0;
        if (strcmp(tmp.owner, username) == 0) {
            favs[*out_count] = tmp;
            (*out_count)++;
        }
    }
    fclose(f);
    return *out_count;
}

int load_user_friends(const char *username, FriendRel frs[], int max, int *out_count) {
    if (!username || !frs || !out_count) return -1;
    *out_count = 0;
    FILE *f = fopen("data/friends.txt", "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f) && *out_count < max) {
        if (line[0] == '#' || line[0] == '\n') continue;
        line[strcspn(line, "\r\n")]='\0';
        FriendRel tmp;
        char *tok, *saveptr = NULL;
        tok = strtok_r(line, "|", &saveptr); if (tok) tmp.user_a = tok;
        tok = strtok_r(NULL, "|", &saveptr); if (tok) tmp.user_b = tok;
        tok = strtok_r(NULL, "|", &saveptr); tmp.since = tok ? (time_t)atol(tok) : 0;
        if (strcmp(tmp.user_a, username) == 0 || strcmp(tmp.user_b, username) == 0) {
            frs[*out_count] = tmp;
            (*out_count)++;
        }
    }
    fclose(f);
    return *out_count;
}

int load_user_requests(const char *username, FriendRequest reqs[], int max, int *out_count) {
    if (!username || !reqs || !out_count) return -1;
    *out_count = 0;
    FILE *f = fopen("data/requests.txt", "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f) && *out_count < max) {
        if (line[0] == '#' || line[0] == '\n') continue;
        line[strcspn(line, "\r\n")]='\0';
        FriendRequest tmp;
        char *tok, *saveptr = NULL;
        tok = strtok_r(line, "|", &saveptr); if (!tok) continue; tmp.id = atoi(tok);
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.from = tok;
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.to = tok;
        tok = strtok_r(NULL, "|", &saveptr); tmp.created_at = tok ? (time_t)atol(tok) : 0;
        if (strcmp(tmp.from, username) == 0) {
            reqs[*out_count] = tmp;
            (*out_count)++;
        }
    }
    fclose(f);
    return *out_count;
}

int load_user_notifications(const char *username, Notification notifs[], int max, int *out_count) {
    if (!username || !notifs || !out_count) return -1;
    *out_count = 0;
    FILE *f = fopen("data/notifications.txt", "r");
    if (!f) return -1;
    char line[1024];
    while (fgets(line, sizeof(line), f) && *out_count < max) {
        if (line[0] == '#' || line[0] == '\n') continue;
        line[strcspn(line, "\r\n")]='\0';
        char *tok, *saveptr = NULL;
        Notification tmp;
        tok = strtok_r(line, "|", &saveptr); if (!tok) continue; tmp.id = atoi(tok);
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.to = tok;
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.from = tok;
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.fav_id = atoi(tok);
        tok = strtok_r(NULL, "|", &saveptr); if (!tok) continue; tmp.message = tok;
        tok = strtok_r(NULL, "|", &saveptr); tmp.seen = tok ? atoi(tok) : 0;
        tok = strtok_r(NULL, "|", &saveptr); tmp.created_at = tok ? (time_t)atol(tok) : 0;
        if (strcmp(tmp.to, username) == 0) {
            notifs[*out_count] = tmp;
            (*out_count)++;
        }
    }
    fclose(f);
    return *out_count;
}

find_account(const char *username) {
    for (int i = 0; i < accountCount; i++) {
        if (strcmp(accounts[i].username, username) == 0) {
            return &accounts[i];
        }
    }
    return NULL;
}

int create_account(const char *username, const char *password) {
    if (!username || !password) return -1;

    pthread_mutex_lock(&account_lock);

    // Check if username already exists
    for (int i = 0; i < accountCount; i++) {
        if (strcmp(accounts[i].username, username) == 0) {
            pthread_mutex_unlock(&account_lock);
            return -2; // username already exists
        }
    }

    if (accountCount >= MAX_USER) {
        pthread_mutex_unlock(&account_lock);
        return -1; // server full
    }

    // Create new account
    Account new_acc;
    strncpy(new_acc.username, username, sizeof(new_acc.username)-1);
    new_acc.username[sizeof(new_acc.username)-1] = '\0';
    strncpy(new_acc.password, password, sizeof(new_acc.password)-1);
    new_acc.password[sizeof(new_acc.password)-1] = '\0';
    new_acc.status = 1;
    new_acc.is_logged_in = 0;
    new_acc.tagged[0] = '\0';

    accounts[accountCount] = new_acc;
    accountCount++;

    // Save account to file
    char line[128];
    snprintf(line, sizeof(line), "%s|%s|1|", username, password);
    FILE *f = fopen("account.txt", "a");
    if (f) {
        fprintf(f, "%s\n", line);
        fclose(f);
    } else {
        perror("fopen account.txt");
    }

    pthread_mutex_unlock(&account_lock);
    return 0;
}


int create_friend_request(const char *from, const char *to) {
    int new_id = get_next_id_from_file("data/requests.txt");
    char line[256];
    snprintf(line, sizeof(line), "%d|%s|%s|%ld", new_id, from, to, time(NULL));
    return append_line_to_file("data/requests.txt", line);
}
