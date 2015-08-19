#include "logging.h"
#include <unistd.h>

void log_msg_udp(struct log_context *logctx, char *msg);
void log_msg_tcp(struct log_context *logctx, char *msg);

int log_init_remote(struct log_context *logctx,
		    struct confread_section *conf_sect)
{
	char *str = 0;
	char *msg = 0;
	char *remote_logging_addr;
	char *remote_logging_port;

	// load log file format
	str = confread_find_value(conf_sect, "format");
	if (!str || !strncmp(str, "text", 4)) {
		logctx->remote_format = TYPE_TEXT;
	} else if (strncmp(str, "cef", 3) == 0) {
		logctx->remote_format = TYPE_CEF;
	} else {
		fprintf(stderr,
			"Log Config error: [remote.format] unknown format: %s\n",
			str);
		return -1;
	}

	// load log file transport
	str = confread_find_value(conf_sect, "transport");
	if (!str || !strncmp(str, "udp", 3)) {
		logctx->remote_type = TRANS_UDP;
	} else if (!strncmp(str, "tcp", 3)) {
		logctx->remote_type = TRANS_TCP;
	} else {
		fprintf(stderr,
			"Log Config error: [remote.transport] unknown transport: %s\n",
			str);
		return -1;
	}

	// load remote logging info

	str = confread_find_value(conf_sect, "remotehost");
	remote_logging_addr = malloc((sizeof(char) * strlen(str)) + 1);
	memcpy(remote_logging_addr, str, strlen(str) + 1);

	str = confread_find_value(conf_sect, "remoteport");
	remote_logging_port = malloc((sizeof(char) * strlen(str)) + 1);
	memcpy(remote_logging_port, str, strlen(str) + 1);

	bzero(&(logctx->remote_addr), sizeof(logctx->remote_addr));
	logctx->remote_addr.sin_family = AF_INET;
	inet_aton(remote_logging_addr, &logctx->remote_addr.sin_addr);
	logctx->remote_addr.sin_port = htons(atoi(remote_logging_port));

	free(remote_logging_port);
	free(remote_logging_addr);

	// rate limit load
	logctx->remote_ratelimit = rate_limit_config(conf_sect);

	switch (logctx->remote_format) {
	case TYPE_TEXT:
		msg = "Logging Started";
		break;
	case TYPE_CEF:
		msg = "CEF:0|||||Tripwire Logging started|2|";
		break;
	}

	switch (logctx->remote_type) {
	case TRANS_UDP:
		log_msg_udp(logctx, msg);
		break;
	case TRANS_TCP:
		log_msg_tcp(logctx, msg);
		break;
	}

	// log file is enabled
	logctx->method = logctx->method | METHOD_REMOTE;

	return 0;

}

void log_flush_remote(struct log_context *logctx)
{
	char *msg = 0;

	// check to see if we have a rate limit catchup to send
	if (logctx->remote_limited && check_limit(logctx->remote_ratelimit, 0)) {

		msg = malloc(MAX_PACKET_SIZE + 1);
		bzero(msg, MAX_PACKET_SIZE + 1);

		switch (logctx->remote_format) {
		case TYPE_TEXT:
			snprintf(msg, MAX_PACKET_SIZE,
				 "Tripwire has dropped %d events due to ratelimiting\n",
				 logctx->remote_limited);
			break;
		case TYPE_CEF:
			snprintf(msg, MAX_PACKET_SIZE,
				 "CEF:0|||||Tripwire Rate Limiting Activated.||msg=Tripware has dropped %d events due to ratelimiting",
				 logctx->remote_limited);
			break;
		}
		switch (logctx->remote_type) {
		case TRANS_UDP:
			log_msg_udp(logctx, msg);
			break;
		case TRANS_TCP:
			log_msg_tcp(logctx, msg);
			break;
		}

		free(msg);
		logctx->remote_limited = 0;
	}
}

void log_event_remote(struct log_context *logctx, struct sockaddr_in *remote,
		      struct sockaddr_in *local)
{
	char *msg = 0;

	// check for rate limiting
	if (logctx->remote_ratelimit
	    && !check_limit(logctx->remote_ratelimit, 1)) {
		logctx->remote_limited++;
	} else {
		// flush logs and catch up alerts
		log_flush(logctx);

		// send alert
		switch (logctx->remote_format) {
		case TYPE_TEXT:
			text_format(&msg, remote, local, logctx);
			break;
		case TYPE_CEF:
			cef_format(&msg, remote, local, logctx);
			break;
		}

		// send alert to remote location
		switch (logctx->remote_type) {
		case TRANS_UDP:
			log_msg_udp(logctx, msg);
			break;
		case TRANS_TCP:
			log_msg_tcp(logctx, msg);
			break;
		}

		// free the message allocated by *_format()
		free(msg);
	}
}

void log_close_remote(struct log_context *logctx)
{

	char *msg = 0;

	switch (logctx->remote_format) {
	case TYPE_TEXT:
		msg = "Logging Stopped";
		break;
	case TYPE_CEF:
		msg = "CEF:0|||||Tripwire Logging stopped|6|";
		break;
	}

	switch (logctx->remote_type) {
	case TRANS_UDP:
		log_msg_udp(logctx, msg);
		break;
	case TRANS_TCP:
		log_msg_tcp(logctx, msg);
		break;
	}

	// remove file logging method
	logctx->method = logctx->method & ~METHOD_REMOTE;
}

void log_msg_udp(struct log_context *logctx, char *msg)
{

	int sockfd = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("UDP Socket failed");
		return;
	}

	sendto(sockfd, msg, strlen(msg), 0,
	       (struct sockaddr *)&(logctx->remote_addr),
	       sizeof(logctx->remote_addr));

}

void log_msg_tcp(struct log_context *logctx, char *msg)
{

	int sockfd = 0;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("TCP socket failed");
		return;
	}

	if (connect
	    (sockfd, (struct sockaddr *)&(logctx->remote_addr),
	     sizeof(logctx->remote_addr)) == -1) {
		perror("TCP failed to connect");
		return;
	}

	send(sockfd, msg, strlen(msg), 0);

	close(sockfd);
}
