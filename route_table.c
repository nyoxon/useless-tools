// educational example fo how
// access the kernel route table
// uselessness = 7/10

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#define BUFFER_SIZE 8192

static void
print_route(struct nlmsghdr* nlh)
{
	struct rtmsg* rtm = NLMSG_DATA(nlh);
	
	if (rtm->rtm_family != AF_INET) {
		return;
	}
	
	struct in_addr dst = {0};
	struct in_addr gateway = {0};
	
	unsigned int oif = 0;
	unsigned int metric = 0;
	unsigned int table = rtm->rtm_table;
	
	int attr_len = RTM_PAYLOAD(nlh);
	
	for (struct rtattr* attr = RTM_RTA(rtm);
	     RTA_OK(attr, attr_len);
	     attr = RTA_NEXT(attr, attr_len))
	{
		switch (attr->rta_type) {
		case RTA_DST:
			memcpy(&dst, RTA_DATA(attr), sizeof(dst));
			break;
		
		case RTA_GATEWAY:
			memcpy(&gateway, RTA_DATA(attr), sizeof(gateway));
			break;
		
		case RTA_OIF:
			memcpy(&oif, RTA_DATA(attr), sizeof(oif));
			break;
		
		case RTA_PRIORITY:
			memcpy(&metric, RTA_DATA(attr), sizeof(metric));
			break;
		
		case RTA_TABLE:
			memcpy(&table, RTA_DATA(attr), sizeof(table));
			break;
		}
	}
	
	char dst_str[INET_ADDRSTRLEN];
	char gateway_str[INET_ADDRSTRLEN];
	char ifname[IF_NAMESIZE];
	
	inet_ntop(AF_INET, &dst, dst_str, sizeof(dst_str));
	inet_ntop(AF_INET, &gateway, gateway_str, sizeof(gateway_str));
	
	if (!oif || !if_indextoname(oif, ifname)) {
		snprintf(ifname, sizeof(ifname), "?");
	}
	
	printf(
		"%-16s/%-2u %-16s %-10s %-8u %u\n",
		dst_str,
		rtm->rtm_dst_len,
		gateway.s_addr ? gateway_str : "-",
		ifname,
		metric,
		table
	);
}

int
main(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	
	struct sockaddr_nl kernel = {
		.nl_family = AF_NETLINK
	};
	
	if (bind(fd, (struct sockaddr*) &kernel, sizeof(kernel)) < 0) {
		perror("bind");
		return 1;
	}
	
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} req = {0};
	
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_type = RTM_GETROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = 1;
	
	req.rtm.rtm_family = AF_INET;
	
	if (sendto(fd, &req, req.nlh.nlmsg_len, 0, (struct sockaddr*) &kernel, sizeof(kernel)) < 0) {
		perror("sendto");
		return 1;
	}
	
	printf(
		"%-16s %-3s %-16s %-10s %-8s %s\n",
		"Destination", "Pre", "Gateway",
		"Interface", "Metric", "Table"
	);
	
	char buffer[BUFFER_SIZE];
	
	for (;;) {
		ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
		
		if (len < 0) {
			if (errno = EINTR) {
				continue;
			}
			
			perror("recv");
			break;
		}
		
		int remaining = (int) len;
		
		for (struct nlmsghdr* nlh = (struct nlmsghdr*) buffer;
		     NLMSG_OK(nlh, remaining);
		     nlh = NLMSG_NEXT(nlh, remaining))
		{
			if (nlh->nlmsg_seq != 1) {
				continue;
			}
			
			if (nlh->nlmsg_type == NLMSG_DONE) {
				goto done;
			}
			
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr* err = NLMSG_DATA(nlh);
				
				if (err->error) {
					errno = -err->error;
					perror("netlink");
				}
				
				goto done;
			}
			
			if (nlh->nlmsg_type == RTM_NEWROUTE) {
				print_route(nlh);
			}
		}
	}

done:
	close(fd);
	return 0;
}