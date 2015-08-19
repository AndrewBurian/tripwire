#ifndef LOGGING_H
#define LOGGING_H

#include <arpa/inet.h>
#include "confread.h"
#include "ratelimit.h"

#define MAX_TEXT_MSG 2046
#define MAX_CEF_MSG 1024
#define MAX_HOSTNAME 64

#define METHOD_LOG    0x1
#define METHOD_SYSLOG 0x2
#define METHOD_REMOTE 0x4

#define TYPE_TEXT 1
#define TYPE_CEF 2

#define TRANS_UDP 1
#define TRANS_TCP 0

#define MAX_PACKET_SIZE 1024

struct log_context {
	uint8_t method;

	int file_format;
	FILE *file_fd;
	struct rate_limit *file_ratelimit;
	int file_limited;

	int syslog_format;
	int syslog_level;
	struct rate_limit *syslog_ratelimit;
	int syslog_limited;

	int remote_format;
	int remote_severity;
	int remote_type;
	struct sockaddr_in remote_addr;
	struct rate_limit *remote_ratelimit;
	int remote_limited;

};

// global log functions
struct log_context *log_init(struct confread_file *config_file);
void log_close(struct log_context *log_ctx);
void log_event(struct log_context *logctx, struct sockaddr_in *remote,
	       struct sockaddr_in *local);
void log_flush(struct log_context *logctx);
struct rate_limit *rate_limit_config(struct confread_section *conf_sect);

// formatting functions
void text_format(char **msg, struct sockaddr_in *remote,
		 struct sockaddr_in *local, struct log_context *ctx);
void cef_format(char **msg, struct sockaddr_in *remote,
		struct sockaddr_in *local, struct log_context *ctx);

// File specific functions
int log_init_file(struct log_context *logctx,
		  struct confread_section *conf_sect);
void log_flush_file(struct log_context *logctx);
void log_event_file(struct log_context *logctx, struct sockaddr_in *remote,
		    struct sockaddr_in *local);
void log_close_file(struct log_context *logctx);

// Syslog specific functions
int log_init_syslog(struct log_context *logctx,
		    struct confread_section *conf_sect);
void log_flush_syslog(struct log_context *logctx);
void log_event_syslog(struct log_context *logctx, struct sockaddr_in *remote,
		      struct sockaddr_in *local);
void log_close_syslog(struct log_context *logctx);

// Remote specific functions
int log_init_remote(struct log_context *logctx,
		    struct confread_section *conf_sect);
void log_flush_remote(struct log_context *logctx);
void log_event_remote(struct log_context *logctx, struct sockaddr_in *remote,
		      struct sockaddr_in *local);
void log_close_remote(struct log_context *logctx);

#endif
