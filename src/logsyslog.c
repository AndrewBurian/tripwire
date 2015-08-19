#include "logging.h"
#include <stdio.h>
#include <syslog.h>

int log_init_syslog(struct log_context *logctx,
		    struct confread_section *conf_sect)
{

	int facility = 0;
	int severity = 0;
	char *str = 0;

	// Determine syslog facility
	str = confread_find_value(conf_sect, "facility");
	if (!str) {
		facility = 0;
	} else if (strncmp(str, "LOG_AUTH", 8) == 0) {
		facility = LOG_AUTH;
	} else if (strncmp(str, "LOG_AUTHPRIV", 12) == 0) {
		facility = LOG_AUTHPRIV;
	} else if (strncmp(str, "LOG_DAEMON", 10) == 0) {
		facility = LOG_DAEMON;
	} else if (strncmp(str, "LOG_USER", 8) == 0) {
		facility = LOG_USER;
	} else if (strncmp(str, "LOG_LOCAL", 9) == 0) {
		switch (str[9]) {
		case '1':
			facility = LOG_LOCAL1;
			break;
		case '2':
			facility = LOG_LOCAL2;
			break;
		case '3':
			facility = LOG_LOCAL3;
			break;
		case '4':
			facility = LOG_LOCAL4;
			break;
		case '5':
			facility = LOG_LOCAL5;
			break;
		case '6':
			facility = LOG_LOCAL6;
			break;
		case '7':
			facility = LOG_LOCAL7;
			break;
		case '0':
		case 0:
		default:
			facility = LOG_LOCAL0;
			break;
		}
	} else {
		fprintf(stderr,
			"Config error: [syslog.facility] unsupported facility\n");
		return -1;
	}

	// Determine syslog severity
	str = confread_find_value(conf_sect, "severity");
	if (!str || !strncmp(str, "LOG_WARNING", 11)) {
		severity = LOG_WARNING;
	} else if (strncmp(str, "LOG_DEBUG", 9) == 0) {
		severity = LOG_DEBUG;
	} else if (strncmp(str, "LOG_INFO", 8) == 0) {
		severity = LOG_INFO;
	} else if (strncmp(str, "LOG_NOTICE", 10) == 0) {
		severity = LOG_NOTICE;
	} else if (strncmp(str, "LOG_ERR", 7) == 0) {
		severity = LOG_ERR;
	} else if (strncmp(str, "LOG_CRIT", 8) == 0) {
		severity = LOG_CRIT;
	} else if (strncmp(str, "LOG_ALERT", 9) == 0) {
		severity = LOG_ALERT;
	} else if (strncmp(str, "LOG_EMERG", 9) == 0) {
		severity = LOG_EMERG;
	} else {
		fprintf(stderr,
			"Config error: [syslog.level] unsupported level\n");
		return -1;
	}

	// load log file format
	str = confread_find_value(conf_sect, "format");
	if (!str || !strncmp(str, "text", 4)) {
		logctx->syslog_format = TYPE_TEXT;
	} else if (strncmp(str, "cef", 3) == 0) {
		logctx->syslog_format = TYPE_CEF;
	} else {
		fprintf(stderr,
			"Log Config error: [syslog.format] unknown format: %s\n",
			str);
		return -1;
	}

	// enable syslog
	logctx->method = logctx->method | METHOD_SYSLOG;

	logctx->syslog_level = severity;

	openlog("Tripwire", LOG_PID, facility);

	logctx->syslog_ratelimit = rate_limit_config(conf_sect);
	logctx->syslog_limited = 0;

	switch (logctx->syslog_format) {
	case TYPE_TEXT:
		syslog(logctx->syslog_level, "Logging Started");
		break;
	case TYPE_CEF:
		syslog(logctx->syslog_level,
		       "CEF:0|||||Tripwire Logging started|2|");
		break;

	}

	return 0;

}

void log_flush_syslog(struct log_context *logctx)
{
	// check to see if we have a rate limit catchup to send
	if (logctx->syslog_limited && check_limit(logctx->syslog_ratelimit, 0)) {

		switch (logctx->syslog_format) {
		case TYPE_TEXT:
			syslog(logctx->syslog_level,
			       "Ratelimiting blocked %d events",
			       logctx->syslog_limited);
			break;
		case TYPE_CEF:
			syslog(logctx->syslog_level,
			       "CEF:0|||||Tripwire Ratelimiting blocked %d events|9|",
			       logctx->syslog_limited);
			break;
		}
	}
	logctx->syslog_limited = 0;
}

void log_event_syslog(struct log_context *logctx, struct sockaddr_in *remote,
		      struct sockaddr_in *local)
{
	char *msg = 0;

	// check rate limiting
	if (logctx->syslog_ratelimit
	    && !check_limit(logctx->syslog_ratelimit, 1)) {
		logctx->syslog_limited++;
	} else {
		// flush any limited syslogs
		log_flush(logctx);

		// send alert
		switch (logctx->syslog_format) {
		case TYPE_TEXT:
			text_format(&msg, remote, local, logctx);
			break;
		case TYPE_CEF:
			cef_format(&msg, remote, local, logctx);
			break;
		}

		syslog(logctx->syslog_level, "%s", msg);

		free(msg);
	}

}

void log_close_syslog(struct log_context *logctx)
{

	switch (logctx->syslog_format) {
	case TYPE_TEXT:
		syslog(logctx->syslog_level, "Logging Stopped");
		break;
	case TYPE_CEF:
		syslog(logctx->syslog_level,
		       "CEF:0|||||Tripwire Logging stopped|6|");
		break;

	}

	closelog();

	// remove file logging method
	logctx->method = logctx->method & ~METHOD_SYSLOG;
}
