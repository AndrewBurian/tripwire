#include "tripwire.h"
#include "logging.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/epoll.h>
#include <errno.h>

int syn_watch(struct log_context *log_ctx)
{

	int raw_sock = 0;
	struct iphdr *ip_hdr = 0;
	struct tcphdr *tcp_hdr = 0;

	struct sockaddr_in remote = { 0 };
	struct sockaddr_in local = { 0 };
	socklen_t remote_len = 0;

	char recv_buf[2048] = { 0 };
	int recv_count = 0;

	int epollfd = 0;
	struct epoll_event ev = { 0 };
	struct epoll_event *events =
	    (struct epoll_event *)malloc(sizeof(struct epoll_event));
	int event_count = 0;

	raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (raw_sock == -1) {
		perror("Failed to open raw socket");
		free(events);
		return -1;
	}
	// Create epoll descriptor
	epollfd = epoll_create1(0);
	if (epollfd == -1) {
		perror("Failed to create epoll descriptor");
		free(events);
		return -1;
	}
	// set the monitored event to be IN
	ev.events = EPOLLIN;

	ev.data.fd = raw_sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
		perror("Epoll add failed");
		free(events);
		return -1;
	}

	while (tripwire_running) {

		// get events
		if ((event_count = epoll_wait(epollfd, events, 1, 10000)) == -1) {
			if(errno != EINTR){
				perror("Epoll wait failed");
			}
			break;
		}

		if (event_count) {
			recv_count =
			    recvfrom(raw_sock, recv_buf, 2048, 0,
				     (struct sockaddr *)&remote, &remote_len);
			if (recv_count == -1) {
				perror("Failed to recv from");
				break;
			}
			// the ip header is the start of the received buffer
			ip_hdr = (struct iphdr *)recv_buf;
			tcp_hdr =
			    (struct tcphdr *)(recv_buf +
					      (sizeof(struct iphdr)));

			// check if this is a syn
			if (tcp_hdr->syn && !tcp_hdr->ack) {
				remote.sin_addr.s_addr = ip_hdr->saddr;
				remote.sin_port = tcp_hdr->source;
				local.sin_addr.s_addr = ip_hdr->daddr;
				local.sin_port = tcp_hdr->dest;
				log_event(log_ctx, &remote, &local);
			}
		} else {
			log_flush(log_ctx);
		}
	}

	free(events);

	return 0;

}
