#include "database.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>


static sqlite3 *g_db = NULL;

static void copy_text(char *dest, size_t dest_size, const unsigned char *src) {
    if (!dest || dest_size == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    strncpy(dest, (const char *)src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

static int run_simple_sql(const char *sql) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQLite error: %s\n", errmsg ? errmsg : "unknown");
        sqlite3_free(errmsg);
        return -1;
    }
    return 0;
}

int db_initialize(const char *db_path) {
    const char *path = db_path ? db_path : "data/mmt.db";

    if (sqlite3_open(path, &g_db) != SQLITE_OK) {
        fprintf(stderr, "Failed to open DB %s: %s\n", path, sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    run_simple_sql("PRAGMA foreign_keys = ON;");

    if (run_simple_sql(
            "CREATE TABLE IF NOT EXISTS accounts(" \
            "username TEXT PRIMARY KEY," \
            "password TEXT NOT NULL)")) return -1;

        if (run_simple_sql(
            "CREATE TABLE IF NOT EXISTS favorites(" \
            "id INTEGER PRIMARY KEY AUTOINCREMENT," \
            "owner TEXT NOT NULL," \
            "name TEXT NOT NULL," \
            "category TEXT NOT NULL," \
            "location TEXT NOT NULL," \
            "is_shared INTEGER NOT NULL DEFAULT 0," \
            "sharer TEXT DEFAULT ''," \
            "tagged TEXT DEFAULT ''," \
            "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
            "FOREIGN KEY(owner) REFERENCES accounts(username) ON DELETE CASCADE)")) return -1;

    if (run_simple_sql(
            "CREATE TABLE IF NOT EXISTS friendships(" \
            "id INTEGER PRIMARY KEY AUTOINCREMENT," \
            "user_a TEXT NOT NULL," \
            "user_b TEXT NOT NULL," \
            "since INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
            "UNIQUE(user_a, user_b)," \
            "FOREIGN KEY(user_a) REFERENCES accounts(username) ON DELETE CASCADE," \
            "FOREIGN KEY(user_b) REFERENCES accounts(username) ON DELETE CASCADE)")) return -1;

    if (run_simple_sql(
            "CREATE TABLE IF NOT EXISTS friend_requests(" \
            "id INTEGER PRIMARY KEY AUTOINCREMENT," \
            "requester TEXT NOT NULL," \
            "requestee TEXT NOT NULL," \
            "status INTEGER NOT NULL DEFAULT 0," \
            "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
            "FOREIGN KEY(requester) REFERENCES accounts(username) ON DELETE CASCADE," \
            "FOREIGN KEY(requestee) REFERENCES accounts(username) ON DELETE CASCADE)")) return -1;

    if (run_simple_sql(
            "CREATE TABLE IF NOT EXISTS notifications(" \
            "id INTEGER PRIMARY KEY AUTOINCREMENT," \
            "recipient TEXT NOT NULL," \
            "actor TEXT NOT NULL," \
            "fav_id INTEGER," \
            "message TEXT NOT NULL," \
            "seen INTEGER NOT NULL DEFAULT 0," \
            "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
            "FOREIGN KEY(recipient) REFERENCES accounts(username) ON DELETE CASCADE," \
            "FOREIGN KEY(actor) REFERENCES accounts(username) ON DELETE CASCADE)")) return -1;

    return 0;
}

void db_shutdown(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
}

int db_fetch_accounts(Account accounts[], int max_users, int *out_count) {
    if (!g_db || !out_count || max_users <= 0) return -1;

    *out_count = 0;
    if (!accounts) return 0;

    const char *sql = "SELECT username, password FROM accounts ORDER BY username";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < max_users) {
        copy_text(accounts[idx].username, sizeof(accounts[idx].username), sqlite3_column_text(stmt, 0));
        copy_text(accounts[idx].password, sizeof(accounts[idx].password), sqlite3_column_text(stmt, 1));
        accounts[idx].is_logged_in = 0;
        idx++;
    }

    sqlite3_finalize(stmt);
    *out_count = idx;
    return 0;
}

int db_create_account(const char *username, const char *password) {
    if (!g_db || !username || !password) return -1;

    const char *sql = "INSERT INTO accounts(username, password) VALUES(?, ?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_CONSTRAINT) return -2;
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_fetch_user_favorites(const char *owner, FavoritePlace favs[], int max_items, int *out_count) {
    if (!g_db || !owner || !out_count || max_items <= 0) return -1;

    *out_count = 0;
    if (!favs) return 0;

    const char *sql =
        "SELECT id, name, category, location, is_shared, COALESCE(sharer,''), COALESCE(tagged,'')," \
        " COALESCE(created_at,0) FROM favorites WHERE owner = ? ORDER BY created_at DESC";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_TRANSIENT);

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < max_items) {
        favs[idx].id = sqlite3_column_int(stmt, 0);
        copy_text(favs[idx].name, sizeof(favs[idx].name), sqlite3_column_text(stmt, 1));
        copy_text(favs[idx].category, sizeof(favs[idx].category), sqlite3_column_text(stmt, 2));
        copy_text(favs[idx].location, sizeof(favs[idx].location), sqlite3_column_text(stmt, 3));
        favs[idx].is_shared = sqlite3_column_int(stmt, 4);
        copy_text(favs[idx].sharer, sizeof(favs[idx].sharer), sqlite3_column_text(stmt, 5));
        copy_text(favs[idx].tagged, sizeof(favs[idx].tagged), sqlite3_column_text(stmt, 6));
        favs[idx].created_at = (time_t)sqlite3_column_int64(stmt, 7);
        idx++;
    }

    sqlite3_finalize(stmt);
    *out_count = idx;
    return 0;
}

int db_fetch_user_friends(const char *username, FriendRel friends[], int max_items, int *out_count) {
    if (!g_db || !username || !out_count || max_items <= 0) return -1;

    *out_count = 0;
    if (!friends) return 0;

    const char *sql =
        "SELECT user_a, user_b, since FROM friendships "
        "WHERE user_a = ? OR user_b = ? ORDER BY since DESC";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < max_items) {
        copy_text(friends[idx].user_a, sizeof(friends[idx].user_a), sqlite3_column_text(stmt, 0));
        copy_text(friends[idx].user_b, sizeof(friends[idx].user_b), sqlite3_column_text(stmt, 1));
        friends[idx].since = (time_t)sqlite3_column_int64(stmt, 2);
        idx++;
    }

    sqlite3_finalize(stmt);
    *out_count = idx;
    return 0;
}

int db_fetch_user_requests(const char *username, FriendRequest requests[], int max_items, int *out_count) {
    if (!g_db || !username || !out_count || max_items <= 0) return -1;

    *out_count = 0;
    if (!requests) return 0;

    const char *sql =
        "SELECT id, requester, requestee, status, created_at FROM friend_requests "
        "WHERE requester = ? ORDER BY created_at DESC";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < max_items) {
        requests[idx].id = sqlite3_column_int(stmt, 0);
        copy_text(requests[idx].from, sizeof(requests[idx].from), sqlite3_column_text(stmt, 1));
        copy_text(requests[idx].to, sizeof(requests[idx].to), sqlite3_column_text(stmt, 2));
        requests[idx].status = sqlite3_column_int(stmt, 3);
        requests[idx].created_at = (time_t)sqlite3_column_int64(stmt, 4);
        idx++;
    }

    sqlite3_finalize(stmt);
    *out_count = idx;
    return 0;
}

int db_fetch_user_notifications(const char *username, Notification notifications[], int max_items, int *out_count) {
    if (!g_db || !username || !out_count || max_items <= 0) return -1;

    *out_count = 0;
    if (!notifications) return 0;

    const char *sql =
        "SELECT id, recipient, actor, fav_id, message, seen, created_at FROM notifications "
        "WHERE recipient = ? ORDER BY created_at DESC";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < max_items) {
        notifications[idx].id = sqlite3_column_int(stmt, 0);
        copy_text(notifications[idx].to, sizeof(notifications[idx].to), sqlite3_column_text(stmt, 1));
        copy_text(notifications[idx].from, sizeof(notifications[idx].from), sqlite3_column_text(stmt, 2));
        notifications[idx].fav_id = sqlite3_column_int(stmt, 3);
        copy_text(notifications[idx].message, sizeof(notifications[idx].message), sqlite3_column_text(stmt, 4));
        notifications[idx].seen = sqlite3_column_int(stmt, 5);
        notifications[idx].created_at = (time_t)sqlite3_column_int64(stmt, 6);
        idx++;
    }

    sqlite3_finalize(stmt);
    *out_count = idx;
    return 0;
}

int db_create_favorite(const char *owner, const char *name, const char *category, const char *location) {
    if (!g_db || !owner || !name || !category || !location) return -1;

    const char *sql =
        "INSERT INTO favorites(owner, name, category, location, is_shared, sharer, tagged, created_at) "
        "VALUES(?, ?, ?, ?, 0, '', '', strftime('%s','now'))";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, location, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;

    sqlite3_int64 row_id = sqlite3_last_insert_rowid(g_db);
    if (row_id > INT_MAX) return -1;
    return (int)row_id;
}

int db_update_favorite(int fav_id, const char *owner, const char *name, const char *category, const char *location) {
    if (!g_db || fav_id <= 0 || !owner || !name || !category || !location) return -1;

    const char *sql =
        "UPDATE favorites SET name = ?, category = ?, location = ? WHERE id = ? AND owner = ?";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, location, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, fav_id);
    sqlite3_bind_text(stmt, 5, owner, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    int changed = sqlite3_changes(g_db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;
    if (changed == 0) return -2;
    return 0;
}

int db_create_friend_request(const char *from_user, const char *to_user) {
    if (!g_db || !from_user || !to_user) return -1;

    const char *sql =
        "INSERT INTO friend_requests(requester, requestee, status, created_at) "
        "VALUES(?, ?, 0, strftime('%s','now'))";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, from_user, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, to_user, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_CONSTRAINT) return -2;
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_get_friend_request(int request_id, FriendRequest *out_request) {
    if (!g_db || !out_request || request_id <= 0) return -1;

    const char *sql =
        "SELECT id, requester, requestee, status, created_at FROM friend_requests WHERE id = ?";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, request_id);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;
    }

    out_request->id = sqlite3_column_int(stmt, 0);
    copy_text(out_request->from, sizeof(out_request->from), sqlite3_column_text(stmt, 1));
    copy_text(out_request->to, sizeof(out_request->to), sqlite3_column_text(stmt, 2));
    out_request->status = sqlite3_column_int(stmt, 3);
    out_request->created_at = (time_t)sqlite3_column_int64(stmt, 4);

    sqlite3_finalize(stmt);
    return 0;
}

int db_accept_friend_request(int request_id, const char *requestee) {
    if (!g_db || !requestee || request_id <= 0) return -1;

    char *errmsg = NULL;
    if (sqlite3_exec(g_db, "BEGIN IMMEDIATE", NULL, NULL, &errmsg) != SQLITE_OK) {
        if (errmsg) sqlite3_free(errmsg);
        return -1;
    }

    const char *select_sql =
        "SELECT requester, requestee, status FROM friend_requests WHERE id = ?";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, select_sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, request_id);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return -2;
    }

    char requester[MAX_NAME_LEN];
    char requestee_db[MAX_NAME_LEN];
    copy_text(requester, sizeof(requester), sqlite3_column_text(stmt, 0));
    copy_text(requestee_db, sizeof(requestee_db), sqlite3_column_text(stmt, 1));
    int status = sqlite3_column_int(stmt, 2);
    sqlite3_finalize(stmt);

    if (strcmp(requestee_db, requestee) != 0) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return -4;
    }
    if (status != 0) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return -3;
    }

    char user_a[MAX_NAME_LEN];
    char user_b[MAX_NAME_LEN];
    if (strcmp(requester, requestee_db) < 0) {
        strncpy(user_a, requester, sizeof(user_a));
        strncpy(user_b, requestee_db, sizeof(user_b));
    } else {
        strncpy(user_a, requestee_db, sizeof(user_a));
        strncpy(user_b, requester, sizeof(user_b));
    }
    user_a[sizeof(user_a) - 1] = '\0';
    user_b[sizeof(user_b) - 1] = '\0';

    const char *insert_friend_sql =
        "INSERT OR IGNORE INTO friendships(user_a, user_b, since) "
        "VALUES(?, ?, strftime('%s','now'))";

    if (sqlite3_prepare_v2(g_db, insert_friend_sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, user_a, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user_b, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    const char *update_sql = "UPDATE friend_requests SET status = 1 WHERE id = ?";
    if (sqlite3_prepare_v2(g_db, update_sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, request_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    if (sqlite3_exec(g_db, "COMMIT", NULL, NULL, &errmsg) != SQLITE_OK) {
        if (errmsg) sqlite3_free(errmsg);
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    return 0;
}

int db_mark_notification_seen(int notif_id) {
    if (!g_db) return -1;

    const char *sql = "UPDATE notifications SET seen = 1 WHERE id = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, notif_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}
