#include "logging.h"

int log_init_file(struct log_context *logctx,
		  struct confread_section *conf_sect)
{

	char *str = 0;
	char time_str[64] = { 0 };
	struct tm *time_struct;
	time_t t;

	// log file is enabled
	logctx->method = logctx->method | METHOD_LOG;

	// load log file path
	str = confread_find_value(conf_sect, "path");

	if (!str) {
		logctx->file_fd = fopen("/var/log/tripwire/tripwire.log", "a");
	} else {
		logctx->file_fd = fopen(str, "a");
	}

	if (!logctx->file_fd) {
		fprintf(stderr, "Log Error: failed to open file %s ", str);
		perror("");
		return -1;
	}
	// load log file format
	str = confread_find_value(conf_sect, "format");
	if (!str || !strncmp(str, "text", 4)) {
		logctx->file_format = TYPE_TEXT;
	} else if (strncmp(str, "cef", 3) == 0) {
		logctx->file_format = TYPE_CEF;
	} else {
		fprintf(stderr,
			"Log Config error: [logfile.format] unknown format: %s\n",
			str);
		return -1;
	}
	// rate limit load
	logctx->file_ratelimit = rate_limit_config(conf_sect);

	t = time(0);
	time_struct = localtime(&t);
	strftime(time_str, 64, "%F %T", time_struct);

	switch (logctx->file_format) {
	case TYPE_TEXT:
		fprintf(logctx->file_fd, "%s: %s\n", time_str,
			"Logging Started");
		break;
	case TYPE_CEF:
		fprintf(logctx->file_fd, "%s: %s\n", time_str,
			"CEF:0|||||Tripwire Logging started|2|");
		break;

	}

	// write immediatly
	fflush(logctx->file_fd);

	return 0;

}

void log_flush_file(struct log_context *logctx)
{

	time_t t = time(0);
	struct tm *time_struct = localtime(&t);
	char time_str[64] = { 0 };

	// check to see if we have a rate limit catchup to send
	if (logctx->file_limited && check_limit(logctx->file_ratelimit, 0)) {

		// get the local time for the logfile
		strftime(time_str, 64, "%F %T", time_struct);

		switch (logctx->file_format) {
		case TYPE_TEXT:
			fprintf(logctx->file_fd,
				"%s: Tripwire ratelimiting blocked %d events\n",
				time_str, logctx->file_limited);
			break;
		case TYPE_CEF:
			fprintf(logctx->file_fd,
				"%s: CEF:0|||||Tripwire Ratelimiting blocked %d events|9|\n",
				time_str, logctx->file_limited);
			break;
		}
		fflush(logctx->file_fd);
		logctx->file_limited = 0;
	}
}

void log_event_file(struct log_context *logctx, struct sockaddr_in *remote,
		    struct sockaddr_in *local)
{

	char *msg = 0;
	char time_str[64] = { 0 };
	struct tm *time_struct;
	time_t t;

	// check for rate limiting
	if (logctx->file_ratelimit && !check_limit(logctx->file_ratelimit, 1)) {
		logctx->file_limited++;
	} else {
		// flush logs and catch up alerts
		log_flush(logctx);

		t = time(0);
		time_struct = localtime(&t);
		strftime(time_str, 64, "%F %T", time_struct);

		// send alert
		switch (logctx->file_format) {
		case TYPE_TEXT:
			text_format(&msg, remote, local, logctx);
			fprintf(logctx->file_fd, "%s: %s\n", time_str, msg);
			break;
		case TYPE_CEF:
			cef_format(&msg, remote, local, logctx);
			fprintf(logctx->file_fd, "%s: %s\n", time_str, msg);
			break;
		}

		// write immediatly
		fflush(logctx->file_fd);

		// free the message allocated by *_format()
		free(msg);
	}

}

void log_close_file(struct log_context *logctx)
{

	char time_str[64] = { 0 };
	struct tm *time_struct;
	time_t t;

	t = time(0);
	time_struct = localtime(&t);
	strftime(time_str, 64, "%F %T", time_struct);

	switch (logctx->file_format) {
	case TYPE_TEXT:
		fprintf(logctx->file_fd, "%s: %s\n", time_str,
			"Logging Stopped");
		break;
	case TYPE_CEF:
		fprintf(logctx->file_fd, "%s: %s\n", time_str,
			"CEF:0|||||Tripwire Logging stopped|6|");
		break;

	}

	// write immediatly
	fflush(logctx->file_fd);
	fclose(logctx->file_fd);

	// remove file logging method
	logctx->method = logctx->method & ~METHOD_LOG;
}
