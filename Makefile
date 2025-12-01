CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_GNU_SOURCE

CLIENT_SRC = TCP_Client/client.c
SERVER_SRC = TCP_Server/server.c
CLIENT_BIN = client
SERVER_BIN = server

.PHONY: all clean

all: $(CLIENT_BIN) $(SERVER_BIN)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $^

$(SERVER_BIN): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(CLIENT_BIN) $(SERVER_BIN) *.o
