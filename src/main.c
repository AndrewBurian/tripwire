#include "tripwire.h"
#include <getopt.h>
#include <stdio.h>
#include "confread.h"
#include "logging.h"
#include <unistd.h>
#include <signal.h>

void sig_handler(int signo);

int main(int argc, char **argv)
{

	char *conf_file_path = 0;
	struct confread_file *conf_file = 0;
	struct confread_section *conf_sect = 0;

	struct log_context *log_ctx = 0;

	struct option long_options[] = {
		{"config", required_argument, 0, 'c'},
		{0, 0, 0, 0}
	};
	char *short_options = "c:";
	int option_index = 0;
	char opt = 0;

	int *ports = 0;
	int port_count = 0;
	char *port_str = 0;
	char *port_str_n = 0;

	char *str = 0;
	int ret = 0;
	size_t i = 0;

	while ((opt =
		getopt_long(argc, argv, short_options, long_options,
			    &option_index))
	       != -1) {

		switch (opt) {
		case ('c'):
			conf_file_path = optarg;
			break;
		}
	}

	// sanity checks
	if (!conf_file_path) {
		conf_file_path = "/etc/tripwire/tripwire.conf";
	}

	if (getuid()) {
		fprintf(stderr,
			"You are not running as root. Root is needed for raw sockets and service ports.\n");
	}
	// Term handler
	tripwire_running = 1;
	if (signal(SIGTERM, sig_handler) == SIG_ERR) {
		fprintf(stderr,
			"Can't catch sigterm. Program will not exit gracefully.\n");
	}
	// Open the config file
	conf_file = confread_open(conf_file_path);
	if (!conf_file) {
		fprintf(stderr, "Failed to open config: %s\n", conf_file_path);
		return -1;
	}
	// Determine if we're doing portwatch or synwatch
	if ((conf_sect = confread_find_section(conf_file, "synwatch"))) {

		str = confread_find_value(conf_sect, "enabled");
		if (str && strncmp(str, "true", 4) == 0) {
			// Synwatch chosen

			// Setup logging
			if ((log_ctx = log_init(conf_file)) == 0) {
				fprintf(stderr, "Logging failed to init\n");
				confread_close(&conf_file);
				return -1;
			}

			confread_close(&conf_file);
			ret = syn_watch(log_ctx);
			log_close(log_ctx);
			return ret;
		}
	}
	if ((conf_sect = confread_find_section(conf_file, "portwatch"))) {
		str = confread_find_value(conf_sect, "enabled");
		if (str && strncmp(str, "true", 4) == 0) {

			// Portwatch chosen

			// Setup logging
			if ((log_ctx = log_init(conf_file)) == 0) {
				fprintf(stderr, "Logging failed to init\n");
				confread_close(&conf_file);
				return -1;
			}
			// Parse out ports

			str = confread_find_value(conf_sect, "ports");
			if (!str) {
				fprintf(stderr,
					"Config error: [portwatch.ports] not found\n");
				confread_close(&conf_file);
				return -1;
			}
			// Read the comma separated list of ports
			port_str = str;
			port_str_n = str;

			// Count the commas
			port_count = 1;
			while (*port_str_n) {
				if (*port_str_n == ',') {
					port_count++;
				}
				port_str_n++;
			}
			ports = (int *)malloc(sizeof(int) * port_count);

			// reset and read ports
			port_str_n = port_str;
			for (i = 0; i < port_count; ++i) {
				// find the next comma or end of line
				while ((*port_str_n) != ','
				       && (*port_str_n) != 0) {
					port_str_n++;
				}
				// null the comma to allow sscanf to work
				*port_str_n = 0;

				// scan the port
				ret = sscanf(port_str, "%d", &ports[i]);
				// on fail, omit this port
				if (!ret) {
					port_count--;
					i--;
				}

				port_str = port_str_n + 1;
				port_str_n = port_str;
			}

			// check to see we got some
			if (!port_count) {
				fprintf(stderr,
					"Config error: [portwatch.ports] no valid ports");
				confread_close(&conf_file);
				free(ports);
				return -1;
			}

			confread_close(&conf_file);
			ret = port_watch(ports, port_count, log_ctx);
			free(ports);
			log_close(log_ctx);
			return ret;
		}
	}
	// Arriving here means no sections were enabled
	fprintf(stderr,
		"No watch sections enabled\nEnable either portwatch or synwatch in %s\n",
		conf_file_path);

	confread_close(&conf_file);
	return 0;
}

void sig_handler(int signo)
{
	if (signo == SIGTERM) {
		// done
		tripwire_running = 0;
	}
}
