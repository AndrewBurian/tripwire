#ifndef TRIPWIRE_H
#define TRIPWIRE_H

#include "logging.h"

int tripwire_running;

int syn_watch(struct log_context* log_ctx);
int port_watch(int* ports, int num_ports, struct log_context* log_ctx);

#endif
