#include "logging.h"
#include <unistd.h>

void text_format(char **msg, struct sockaddr_in *remote,
		 struct sockaddr_in *local, struct log_context *ctx)
{

	char *local_name = 0;
	char *remote_name = 0;
	char *tmp = 0;

	char *hostname = malloc(MAX_HOSTNAME + 1);
	bzero(hostname, MAX_HOSTNAME + 1);

	*msg = realloc(*msg, MAX_TEXT_MSG + 1);
	bzero(*msg, MAX_TEXT_MSG + 1);

	// get local hostname
	gethostname(hostname, MAX_HOSTNAME);

	// get the remote name
	tmp = inet_ntoa(remote->sin_addr);
	remote_name = (char *)malloc(sizeof(char) * strlen(tmp));
	strcpy(remote_name, tmp);

	// local name
	tmp = inet_ntoa(local->sin_addr);
	local_name = (char *)malloc(sizeof(char) * strlen(tmp));
	strcpy(local_name, tmp);

	snprintf(*msg, MAX_TEXT_MSG, "%s:%d -> %s:%d (%s)",
		 remote_name, ntohs(remote->sin_port),
		 local_name, ntohs(local->sin_port), hostname);

	free(hostname);
	free(remote_name);
	free(local_name);
}

void cef_format(char **msg, struct sockaddr_in *remote,
		struct sockaddr_in *local, struct log_context *ctx)
{
	char *remote_name = 0;
	char *local_name = 0;
	char *tmp = 0;

	char *hostname = malloc(MAX_HOSTNAME + 1);
	bzero(hostname, MAX_HOSTNAME + 1);

	*msg = realloc(*msg, MAX_CEF_MSG + 1);
	bzero(*msg, MAX_CEF_MSG + 1);

	// get local hostname
	gethostname(hostname, MAX_HOSTNAME);

	// get the remote name
	tmp = inet_ntoa(remote->sin_addr);
	remote_name = (char *)malloc(sizeof(char) * strlen(tmp));
	strcpy(remote_name, tmp);

	// local name
	tmp = inet_ntoa(local->sin_addr);
	local_name = (char *)malloc(sizeof(char) * strlen(tmp));
	strcpy(local_name, tmp);

	snprintf(*msg, MAX_CEF_MSG,
		 "CEF:0|||||Tripwire Alarm|8|dst=%s dpt=%d dhost=%s src=%s spt=%d",
		 local_name, ntohs(local->sin_port), hostname, remote_name,
		 ntohs(remote->sin_port));

	free(hostname);
	free(remote_name);
	free(local_name);
}
