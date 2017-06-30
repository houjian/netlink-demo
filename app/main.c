#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "logger.h"

#define NETLINK_TEST 17
#define MAX_PAYLOAD 1024
#define BUF_SIZE 1024

static void dump_nlmsg(struct nlmsghdr *nlh)
{
	int i, j, len;
	unsigned char *data = NLMSG_DATA(nlh);
	int col = 16;
	int datalen = NLMSG_PAYLOAD(nlh, 0);

	printf("===============DEBUG START===============\n");
	printf("nlmsghdr info (%d):\n", NLMSG_HDRLEN);
	printf("  nlmsg_len\t= %d\n" "  nlmsg_type\t= %d\n"
		"  nlmsg_flags\t= %d\n" "  nlmsg_seq\t= %d\n" "  nlmsg_pid\t= %d\n",
		nlh->nlmsg_len, nlh->nlmsg_type,
		nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);

	printf("nlmsgdata info (%d):\n", datalen);

	for (i = 0; i < datalen; i += col) {
		len = (datalen - i < col) ? (datalen - i) : col;

		printf("  ");
		for (j = 0; j < col; j++) {
			if (j < len)
				printf("%02x ", data[i + j]);
			else
				printf("   ");

		}
		printf("\t");
		for (j = 0; j < len; j++) {
			if (j < len)
				if (isprint(data[i + j]))
					printf("%c", data[i + j]);
				else
					printf(".");
			else
				printf(" ");
		}
		printf("\n");
	}
	printf("===============DEBUG END===============\n");
}

static int init_netlink_socket(int protocol)
{
	int sockfd;
	struct sockaddr_nl nladdr;
	int ret;

	sockfd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (sockfd < 0) {
		LOG_ERROR("socket: %s", strerror(errno));
		return -1;
	}

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = getpid();
	nladdr.nl_groups = 0;

	ret = bind(sockfd, (struct sockaddr *) &nladdr, sizeof(nladdr));
	if (ret < 0) {
		LOG_ERROR("bind: %s", strerror(errno));
		close(sockfd);
		return ret;
	}

	return sockfd;
}

static int test_send_msg(int sockfd, const char *str)
{
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlh;
	int ret;
	int len = strlen(str) + 1;

	nlh = calloc(1, NLMSG_SPACE(len));
	if (!nlh) {
		LOG_ERROR("calloc: alloc nlmsghdr error");
		return -1;
	}
	nlh->nlmsg_len = NLMSG_LENGTH(len);
	nlh->nlmsg_type = 0;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 9527;
	nlh->nlmsg_pid = getpid();
	strcpy(NLMSG_DATA(nlh), str);

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	LOG_INFO("start to send message");

	ret = sendmsg(sockfd, (struct msghdr *) &msg, 0);
	if (ret < 0) {
		LOG_ERROR("sendmsg: %s", strerror(errno));
		free(nlh);
		return ret;
	}

	/* debug info */
	dump_nlmsg(nlh);

	free(nlh);
	return ret;
}

static int test_recv_msg(int sockfd, char *buf, int len)
{
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlh;
	int ret;

	nlh = calloc(1, NLMSG_SPACE(MAX_PAYLOAD));
	if (!nlh) {
		LOG_ERROR("calloc: alloc nlmsghdr error");
		return -1;
	}

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	LOG_INFO("start to recv message");

	ret = recvmsg(sockfd, (struct msghdr *) &msg, 0);
	if (ret < 0) {
		LOG_ERROR("recvmsg: %s", strerror(errno));
		free(nlh);
		return ret;
	}

	strncpy(buf, NLMSG_DATA(nlh), len - 1);
	buf[len] = '\0';

	/* debug info */
	dump_nlmsg(nlh);

	free(nlh);
	return ret;
}

int main()
{
	int sockfd;
	int ret;
	char buf[BUF_SIZE];
	const char *str = "Hello Netlink!";

	sockfd = init_netlink_socket(NETLINK_TEST);
	if (sockfd < 0) {
		LOG_ERROR("init_netlink_socket: couldn't init netlink socket");
		return EXIT_FAILURE;
	}

	ret = test_send_msg(sockfd, str);
	if (ret < 0) {
		LOG_ERROR("test_send_msg: send msg failed");
		close(sockfd);
		return EXIT_FAILURE;
	}

	ret = test_recv_msg(sockfd, buf, sizeof(buf));
	if (ret < 0) {
		LOG_ERROR("test_recv_msg: recv msg failed");
		close(sockfd);
		return EXIT_FAILURE;
	}

	LOG_INFO("receive from kernel: %s", buf);

	close(sockfd);
	return EXIT_SUCCESS;
}
