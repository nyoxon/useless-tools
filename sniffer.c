// sniffer.c
// Compile: gcc -Wall -O2 sniffer.c -o sniffer
// Usage: sudo ./sniffer -i <iface> [-p tcp|udp|icmp|all]
// Note: requires root or CAP_NET_RAW capability.

// uselessness = use tcpdump instead

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>

// max packet size to read
#define BUFSIZE 65536

static void print_mac(const unsigned char *mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static const char* proto_name(int p) {
	switch (p) {
		case IPPROTO_TCP: return "TCP";
		case IPPROTO_UDP: return "UDP";
		case IPPROTO_ICMP: return "ICMP";
		default: return "OTHER";
	}
}

static void parse_args 
(
	int argc, 
	char* argv[], 
	char** iface,
	int* wanted_proto,
	char** target_ip
) 
{
	for (int i=1;i<argc;i++) {
		if (strcmp(argv[i], "-i") == 0 && i+1 < argc) {
			*iface = argv[++i];
		} else if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
			char *p = argv[++i];
			if (strcmp(p, "tcp")==0) *wanted_proto = IPPROTO_TCP;
			else if (strcmp(p, "udp")==0) *wanted_proto = IPPROTO_UDP;
			else if (strcmp(p, "icmp")==0) *wanted_proto = IPPROTO_ICMP;
			else if (strcmp(p, "all")==0) *wanted_proto = -1;
			else {
				fprintf(stderr, "Unknown protocol: %s\n", p);
				exit(1);
			}
		} else if (strcmp(argv[i], "-t") == 0 && i+1 < argc) {
			*target_ip = argv[++i];
		} else {
			fprintf(stderr, "Usage: %s -i <iface> [-p tcp|udp|icmp|all]\n", argv[0]);
			exit(1);
		}
	}
	if (!iface) {
		fprintf(stderr, "Specify interface with -i\n");
		exit(1);
	}    
}

bool parse_target_ip(const char* target_ip, uint32_t* out_target) {
	if (!target_ip) {
		return false;
	}

	struct in_addr a;

	if (inet_pton(AF_INET, target_ip, &a) != 1) {
		return false;
	}

	*out_target = a.s_addr;

	return true;
}

int main(int argc, char *argv[]) {
	char* iface = NULL;
	char* target_ip = NULL;
	int wanted_proto = -1; // -1 = all

	// receive args from command line
	parse_args(argc, argv, &iface, &wanted_proto, &target_ip);

	// create raw socket at link/second layer
	// AF_PACKET is a AF on link-layer packets
	// SOCK_RAW indicates that we want the header of
	// the layer packet entirely
	// ETH_P_ALL indicates that we want all kinds
	// of packets
	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	// ifreq is a struct that allows user-space and kernel
	// communication over properties of 
	// network interfaces via the ioctl syscall
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	// we want the index of the iface inside the kernel,
	// because all low-level operations we want need it
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
		perror("SIOCGIFINDEX");
		close(sockfd);
		return 1;
	}

	// get the index
	int ifindex = ifr.ifr_ifindex;

	// sockaddr_ll is similar to sockaddr_in
	// while the latter is used to internet-layer
	// addresses, the former is used to link-layer
	// addresses.
	// "ll" is to link-layer, "in" is to internet
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex; // that's why we wanted the index
	sll.sll_protocol = htons(ETH_P_ALL);

	// assigns the address to the socket
	if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
		perror("bind");
		close(sockfd);

		return 1;
	}

	printf("Listening on %s (ifindex=%d). Proto filter: %s\n",
		   iface, ifindex, (wanted_proto==-1) ? "ALL" : proto_name(wanted_proto));

	// buffer to hold incoming packets
	unsigned char *buffer = malloc(BUFSIZE);
	if (!buffer) { perror("malloc"); close(sockfd); return 1; }

	while (1) {
		// reads from the socket
		ssize_t len = recvfrom(sockfd, buffer, BUFSIZE, 0, NULL, NULL);

		if (len < 0) {
			if (errno == EINTR) continue;
			perror("recvfrom");
			break;
		}

		time_t t = time(NULL);
		struct tm tm;
		localtime_r(&t, &tm);
		char timestr[64];
		strftime(timestr, sizeof(timestr), "%F %T", &tm);

		if (len < sizeof(struct ethhdr)) continue;

		// ethddr represents the eth header itself
		struct ethhdr *eth = (struct ethhdr*)buffer;

		// only parse IPv4 for now
		if (ntohs(eth->h_proto) != ETH_P_IP) {
			continue;
		}

		// IP header starts after ethernet header
		unsigned char *ip_packet = buffer + sizeof(struct ethhdr);
		size_t ip_len = len - sizeof(struct ethhdr);

		// iphdr represents the ip header itself
		if (ip_len < sizeof(struct iphdr)) continue; // truncated

		struct iphdr *iph = (struct iphdr*)ip_packet;
		// check header length
		int ihl = iph->ihl * 4;

		// minimum ihl = 20 bytes
		if (ip_len < (size_t) ihl) continue;

		uint32_t target_net;
		bool result = parse_target_ip(target_ip, &target_net);

		if (result) {
			if (iph->saddr != target_net && iph->daddr != target_net) {
				continue;
			}
		}

		char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

		// converts binary to text
		inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip));

		int ip_proto = iph->protocol;
		if (wanted_proto != -1 && ip_proto != wanted_proto) continue;

		printf("[%s] ", timestr);
		print_mac(eth->h_source);
		printf(" -> ");
		print_mac(eth->h_dest);
		printf(" | IPv4 %s -> %s | proto=%s", src_ip, dst_ip, proto_name(ip_proto));

		// TCP
		if (ip_proto == IPPROTO_TCP) {
			if (ip_len < (size_t)(ihl + sizeof(struct tcphdr))) { printf(" [TCP truncated]\n"); continue; }
			struct tcphdr *tc = (struct tcphdr*)(ip_packet + ihl);
			printf(" | %u -> %u | seq=%u ack=%u flags=[",
				   ntohs(tc->source), ntohs(tc->dest), ntohl(tc->seq), ntohl(tc->ack_seq));
			if (tc->urg) printf("U");
			if (tc->ack) printf("A");
			if (tc->psh) printf("P");
			if (tc->rst) printf("R");
			if (tc->syn) printf("S");
			if (tc->fin) printf("F");
			printf("]\n");
		}
		// UDP
		else if (ip_proto == IPPROTO_UDP) {
			if (ip_len < (size_t)(ihl + sizeof(struct udphdr))) { printf(" [UDP truncated]\n"); continue; }
			struct udphdr *ud = (struct udphdr*)(ip_packet + ihl);
			printf(" | %u -> %u | len=%u\n", ntohs(ud->source), ntohs(ud->dest), ntohs(ud->len));
		}
		// ICMP
		else if (ip_proto == IPPROTO_ICMP) {
			if (ip_len < (size_t)(ihl + sizeof(struct icmphdr))) { printf(" [ICMP truncated]\n"); continue; }
			struct icmphdr *ic = (struct icmphdr*)(ip_packet + ihl);
			printf(" | type=%u code=%u\n", ic->type, ic->code);
		} else {
			printf("\n");
		}
	}

	free(buffer);
	close(sockfd);
	return 0;
}