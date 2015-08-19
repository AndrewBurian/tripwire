#include <sys/epoll.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include "tripwire.h"
#include "logging.h"

int port_watch(int *ports, int num_ports, struct log_context *log_ctx)
{

	int epollfd = 0;
	struct epoll_event ev = { 0 };
	struct epoll_event *events =
	    (struct epoll_event *)malloc(sizeof(struct epoll_event) *
					 num_ports);

	int *sockets = (int *)malloc(sizeof(int) * num_ports);
	struct sockaddr_in local = { 0 };

	int new_sock = 0;
	int event_count = 0;
	struct sockaddr_in remote = { 0 };
	socklen_t remote_len = sizeof(struct sockaddr_in);
	socklen_t local_len = sizeof(struct sockaddr_in);

	size_t i = 0;
	int opt = 1;

	local.sin_family = AF_INET;

	// Create epoll descriptor
	epollfd = epoll_create1(0);
	if (epollfd == -1) {
		perror("Failed to create epoll descriptor");
		free(sockets);
		free(events);
		return -1;
	}
	// set the monitored event to be IN
	ev.events = EPOLLIN;

	// set up all listening sockets
	for (i = 0; i < num_ports; ++i) {

		// create the sockets
		sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (sockets[i] == -1) {
			perror("Failed to open socket");
			free(sockets);
			free(events);
			return -1;
		}
		// set reuse addr
		if (setsockopt
		    (sockets[i], SOL_SOCKET, SO_REUSEADDR, &opt,
		     sizeof(opt)) == -1) {
			perror("Failed to set socket options");
			free(sockets);
			free(events);
			return -1;
		}
		// set port
		local.sin_port = htons(ports[i]);

		// bind
		if (bind(sockets[i], (struct sockaddr *)&local, sizeof(local))
		    == -1) {
			perror("Failed to bind socket");
			free(sockets);
			free(events);
			return -1;
		}
		// listen
		if (listen(sockets[i], 5) == -1) {
			perror("Failed to setup listen");
			free(sockets);
			free(events);
			return -1;
		}
		// add to epoll
		ev.data.fd = sockets[i];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockets[i], &ev) == -1) {
			perror("Epoll add failed");
			free(sockets);
			free(events);
			return -1;
		}

	}

	// main epoll loop
	while (tripwire_running) {

		// get events
		if ((event_count =
		     epoll_wait(epollfd, events, num_ports, 10000)) == -1) {
			if(errno != EINTR){
				perror("Epoll wait failed");
			}
			break;
		}
		// loop through events
		for (i = 0; i < event_count; ++i) {

			// all sockets can only be returning new connections
			new_sock =
			    accept(events[i].data.fd,
				   (struct sockaddr *)&remote, &remote_len);
			if (new_sock == -1) {
				perror("Accept failed");
				continue;
			}
			// print local port
			if (getsockname
			    (new_sock, (struct sockaddr *)&local,
			     &local_len) == -1) {
				perror("Failed to get socket local port");
			}
			log_event(log_ctx, &remote, &local);

			// close socket
			close(new_sock);
		}

		// timeout for log flushing
		if (!event_count) {
			log_flush(log_ctx);
		}
	}

	free(sockets);
	free(events);
	return 0;
}
