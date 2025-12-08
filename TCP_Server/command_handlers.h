#ifndef TCP_SERVER_COMMAND_HANDLERS_H
#define TCP_SERVER_COMMAND_HANDLERS_H

#include "../entity/entities.h"

void dispatch_command(client_session_t *session, const char *command);

#endif /* TCP_SERVER_COMMAND_HANDLERS_H */
