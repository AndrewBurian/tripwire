#include <arpa/inet.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include "logging.h"
#include "confread.h"
#include <strings.h>
#include <time.h>

struct rate_limit *rate_limit_config(struct confread_section *conf_sect);

struct log_context *log_init(struct confread_file *config_file)
{

	struct log_context *log_ctx =
	    (struct log_context *)malloc(sizeof(struct log_context));
	struct confread_section *conf_sect = 0;
	char *str = 0;

	// zero out all options
	bzero(log_ctx, sizeof(struct log_context));

	// Parse file options
	if ((conf_sect = confread_find_section(config_file, "logfile"))) {

		str = confread_find_value(conf_sect, "enabled");
		if (str && strncmp(str, "true", 4) == 0) {

			// log file enabled
			if (log_init_file(log_ctx, conf_sect) == -1) {
				fprintf(stderr, "Failed to init file log\n");
				free(log_ctx);
				return 0;
			}
		}
	}
	// Parse Syslog options
	if ((conf_sect = confread_find_section(config_file, "syslog"))) {
		str = confread_find_value(conf_sect, "enabled");
		if (str && strncmp(str, "true", 4) == 0) {

			// syslog is enabled
			if (log_init_syslog(log_ctx, conf_sect) == -1) {
				fprintf(stderr, "Failed to init syslog\n");
				free(log_ctx);
				return 0;
			}
		}
	}
	// Parse remote options
	if ((conf_sect = confread_find_section(config_file, "remotelog"))) {
		str = confread_find_value(conf_sect, "enabled");
		if (str && strncmp(str, "true", 4) == 0) {

			// remote is enabled
			if (log_init_remote(log_ctx, conf_sect) == -1) {
				fprintf(stderr, "Failed to init remote log\n");
				free(log_ctx);
				return 0;
			}
		}
	}

	return log_ctx;
}

void log_flush(struct log_context *logctx)
{

	if (logctx->method & METHOD_LOG) {
		// flush the file logs
		log_flush_file(logctx);
	}
	if (logctx->method & METHOD_SYSLOG) {
		// flush the syslog logs
		log_flush_syslog(logctx);
	}
	if (logctx->method & METHOD_REMOTE) {
		// flush remote logs
		log_flush_remote(logctx);
	}
}

void log_event(struct log_context *logctx, struct sockaddr_in *remote,
	       struct sockaddr_in *local)
{

	if (logctx->method & METHOD_LOG) {
		log_event_file(logctx, remote, local);
	}
	if (logctx->method & METHOD_SYSLOG) {
		log_event_syslog(logctx, remote, local);
	}
	if (logctx->method & METHOD_REMOTE) {
		log_event_remote(logctx, remote, local);
	}
}

struct rate_limit *rate_limit_config(struct confread_section *conf_sect)
{

	char *str = 0;
	int burst = 0;
	time_t ti = 0;

	str = confread_find_value(conf_sect, "ratelimit");
	if (str && strncmp(str, "enabled", 7) == 0) {
		// rate limiting enabled

		str = confread_find_value(conf_sect, "rateburst");
		if (!str || sscanf(str, "%d", &burst) != 1) {
			fprintf(stderr,
				"Config error: [%s.rateburst] not found or Nan\n",
				conf_sect->name);
			fprintf(stderr, "  Ratelimiting disabled\n");
			return 0;
		}

		str = confread_find_value(conf_sect, "rateperiod");
		if (!str || sscanf(str, "%ld", &ti) != 1) {
			fprintf(stderr,
				"Config error: [%s.rateperiod] not found or NaN\n",
				conf_sect->name);
			return 0;
		}

		return init_limit(burst, ti);

	}
	// rate limiting not enabled
	return 0;

}

void log_close(struct log_context *log_ctx)
{

	// free all nessesary internal allocations
	if (log_ctx->method & METHOD_LOG) {
		log_close_file(log_ctx);
	}
	if (log_ctx->method & METHOD_SYSLOG) {
		log_close_syslog(log_ctx);
	}
	if (log_ctx->method & METHOD_REMOTE) {
		log_close_remote(log_ctx);
	}

	// free context
	free(log_ctx);
}
