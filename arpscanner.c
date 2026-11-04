// it's not that bad. it's good for learning.
// use 'nmap -sn' instead
// uselessness = 6/10

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <poll.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define MAX_HOSTS 65536u
#define SEND_USLEEP 20000
#define POLL_TIMEOUT_MS 1000
#define REPLY_TIMEOUT_MS 5000
#define RECV_BUF_SIZE 65536

/*
SIMPLIFIED EXAMPLE OF HOW ARP REQUEST WORKS

Host A:
IPv4: 192.168.1.10
MAC: AA:AA:AA:AA:AA:AA

Host B:
IPv4: 192.168.1.15
MAC: BB:BB:BB:BB:BB:BB

Host A wants to send something to Host B where
both are on the same network and he only
knows the destination IP address

Host A build an ARP request:

-- arphrdr (request) --

HTYPE = 1 (ethernet)
PTYPE = 0x0800 (IPv4)
HLEN = 6
PLEN = 4
OPCODE = 1 (request)
SMAC = AA:AA:AA:AA:AA:AA
SIP = 192.168.1.10
TMAC = 00:00:00:00:00:00
TIP = 192.168.1.15
-- --- -- -- 

which is encapsulated in an Ethernet packet:

-- ethhdr -- 

DMAC = FF:FF:FF:FF:FF:FF (broadcast)
SMAC = AA:AA:AA:AA:AA:AA
EtherType = 0x0806 (ARP)
.
.
.
payload = arphdr
-- - -- -- -

now, all the hosts in the same broadcast domain
will receive that packet and only Host B
should reply with a reply:

-- arphdr (reply) --

...
opcode = 2 (reply)
SMAC = BB:BB:BB:BB:BB:BB
SIP = 192.168.1.15
TMAC = AA:AA:AA:AA:AA:AA
TIP = 192.168.1.10

-- -- --- --- --



*/

static volatile sig_atomic_t do_exit = 0;
static void handle_sigint(int _) { (void) _; do_exit = 1; };

struct __attribute__((packed)) arp_hdr {
	uint16_t htype;      // hardware type (1 = Ethernet)
	uint16_t ptype;      // protocol type (ETH_P_IP)
	uint8_t  hlen;       // hardware addr len (6)
	uint8_t  plen;       // protocol addr len (4)
	uint16_t opcode;     // request/reply
	unsigned char sha[6]; // sender hardware addr (MAC)
	unsigned char spa[4]; // sender protocol addr (IPv4)
	unsigned char tha[6]; // target hardware addr (MAC) -- zero for request
	unsigned char tpa[4]; // target protocol addr (IPv4)	
};

struct target {
	uint32_t ip_host;
	bool replied;
	unsigned char mac[6];
	uint64_t sent_ts_ms;
	uint64_t rtt_ms;
};

typedef struct {
	uint32_t first;
	uint32_t last;
	uint32_t network;
	uint32_t broadcast;
	uint64_t n_hosts;
} netinfo;

static void usage(const char* prog) {
	fprintf(stderr,
		"Usage: %s [-i] <interface> [-n] <target>\n"
		"	target can be:\n"
		"		CIDR: 192.168.1.0/24\n"
		"		mask: 192.168.1.0/255.255.255.0\n"
		"		range: 192.168.1.10-192.168.1.250\n"
		"		single: 192.168.1.42\n", prog
	);

	exit(1);
}

static bool str_to_inaddr(const char* s, struct in_addr* out) {
	return inet_pton(AF_INET, s, out) == 1;
}

static int mask_to_prefix(uint32_t mask_host) {
	if (mask_host == 0) {
		return 0;
	}

	if (mask_host == 0xFFFFFFFFu) {
		return 32;
	}

	int cnt = 0;
	uint32_t m = mask_host;

	for (int i = 31; i >= 0; i--) {
		bool bit = (m >> 1) & 1u;

		if (bit) {
			cnt++;
		} else {
			break;
		}
	}

	if (cnt == 0) {
		return (mask_host == 0) ? 0 : -1;
	}

	uint32_t ideal = (cnt == 32) 
		? 0xFFFFFFFFu 
		: (~0u << (32 - cnt));

	return (mask_host == ideal) ? cnt : -1;
}

static uint32_t prefix_to_mask_host(int prefix) {
	if (prefix == 0) {
		return 0u;
	}

	if (prefix == 32) {
		return 0xFFFFFFFFu;
	}

	return (~0u << (32 - prefix));
}

static void ip_host_to_str(uint32_t host_ip, char* buf, size_t bufsz) {
	struct in_addr a;
	a.s_addr = htonl(host_ip);

	inet_ntop(AF_INET, &a, buf, bufsz);
}

static void print_ip_host(uint32_t host_ip) {
	char buffer[INET_ADDRSTRLEN];
	ip_host_to_str(host_ip, buffer, sizeof(buffer));

	printf("%s", buffer);
}

static uint64_t now_ms(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return (uint64_t) tv.tv_sec * 1000ULL + 
		(tv.tv_usec / 1000ULL);
}

static void get_hosts
(
	char* subnet, 
	netinfo* net
) 
{
	char* dash = strchr(subnet, '-');
	char* slash = strchr(subnet, '/');

	uint32_t first_host = 0, last_host = 0;
	bool ok = false;
	
	// range: 192.168.0.1-192.168.0.10
	if (dash) {
		size_t len1 = dash - subnet;
		char left[64], right[64];

		if (len1 >= sizeof(left)) {
			fprintf(stderr, "IP left too long\n");

			exit(1);
		}

		memcpy(left, subnet, len1);
		left[len1] = '\0';

		strncpy(right, dash + 1, sizeof(right) - 1);
		right[sizeof(right) - 1] = '\0';

		struct in_addr a1, a2;

		if (!str_to_inaddr(left, &a1) || 
			!str_to_inaddr(right, &a2)) 
		{
			fprintf(stderr, "invalid range format: %s\n", subnet);

			exit(1);
		}

		uint32_t h1 = ntohl(a1.s_addr);
		uint32_t h2 = ntohl(a2.s_addr);

		if (h1 > h2) {
			uint32_t tmp = h1;
			
			h1 = h2;
			h2 = tmp;
		}

		first_host = h1;
		last_host = h2;

		ok = true;
	} 
	
	// CIDR or mask
	else if (slash) {
		size_t pos = slash - subnet;
		char ipstr[64], tail[64];

		if (pos >= sizeof(ipstr)) {
			fprintf(stderr, "IP too long\n");
			exit(1);
		}

		memcpy(ipstr, subnet, pos);
		ipstr[pos] = '\0';
		
		strncpy(tail, slash + 1, sizeof(tail) - 1);
		tail[sizeof(tail) - 1] = '\0';

		struct in_addr a;

		if (!str_to_inaddr(ipstr, &a)) {
			fprintf(stderr, "invalid ip: %s\n", ipstr);

			exit(1);
		}

		uint32_t ip_host = ntohl(a.s_addr);

		char* endptr = NULL;
		long prefix_val = strtol(tail, &endptr, 10);
		
		// valid CIDR
		if (endptr && 
			*endptr == '\0' && 
			prefix_val >= 0 && 
			prefix_val <= 32) 
		{
			int prefix = (int) prefix_val;
			
			uint32_t mask_host = prefix_to_mask_host(prefix);
			uint32_t network = ip_host & mask_host;
			uint32_t broadcast = network | (~mask_host);

			if (prefix == 32) {
				first_host = last_host = network;
			} 
			
			else if (prefix == 31) {
				first_host = network;
				last_host = broadcast;
			} 
			
			else {
				first_host = network + 1;
				last_host = broadcast - 1;
			}

			ok = true;
		} 
		
		// probably mask
		else {
			struct in_addr mask_addr;

			if (!str_to_inaddr(tail, &mask_addr)) {
				fprintf(stderr, "invalid IP\n");

				exit (1);
			}

			uint32_t mask_host = ntohl(mask_addr.s_addr);
			int prefix = mask_to_prefix(mask_host);

			if (prefix < 0) {
				fprintf(stderr, "invalid netmask\n");

				exit(1);
			}

			uint32_t network = ip_host & mask_host;
			uint32_t broadcast = network | (~mask_host);

			if (prefix == 32) {
				first_host = last_host = network;
			} 
			
			else if (prefix == 31) {
				first_host = network;
				last_host = broadcast;
			} 
			
			else {
				first_host = network + 1;
				last_host = broadcast - 1;
			}

			ok = true;
		}
	} 
	
	// single address
	else {
		struct in_addr a;

		if (!str_to_inaddr(subnet, &a)) {
			fprintf(stderr, "invalid IP\n");

			exit(1);
		}

		uint32_t ip_host = ntohl(a.s_addr);
		first_host = last_host = ip_host;

		ok = true;
	}

	if (!ok) {
		fprintf(stderr, "invalid input");

		exit(1);
	}
	
	// sanity check
	if (first_host > last_host) {
		fprintf(stderr, "invalid interval: first > last\n");
	}

	uint64_t n_hosts = (uint64_t) last_host - 
					   (uint64_t) first_host + 1ULL;
	
	// impossible
	if (n_hosts > MAX_HOSTS) {
		fprintf(stderr, "interval too long");

		exit(2);
	}
	
	// this code snippet attempts mathematically to find a CIDR
	// subnet based on the endpoints of an IP address
	// range. the algorithm tries to infer a minimal subnet
	// not the original to which both address belong

	uint32_t net_mask = 0xFFFFFFFFu;
	uint32_t network_guess = first_host;
	uint32_t broadcast_guess = last_host;

	if (first_host == last_host) {
		network_guess = first_host;
		broadcast_guess = last_host;
	} 
	
	else {
		uint32_t xor = first_host ^ last_host;
		int highest_diff = -1;

		for (int i = 31; i >= 0; i--) {
			if ((xor >> i) & 1u) {
				highest_diff = i;
				break;
			}
		}

		int prefix = (highest_diff == -1) ? 32 : (31 - highest_diff);

		if (prefix < 0) {
			prefix = 0;
		}

		net_mask = prefix_to_mask_host(prefix);
		network_guess = first_host & net_mask;
		broadcast_guess = network_guess | (~net_mask);
	}

	net->first = first_host;
	net->last = last_host;
	net->network = network_guess;
	net->broadcast = broadcast_guess;
	net->n_hosts = n_hosts;
}

static void parse_args
(
	int argc,
	char** argv,
	char** iface,
	char** subnet
)
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			*iface = argv[++i];
		} else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
			*subnet = argv[++i];
		} else {
			usage(argv[0]);
		}
	}

	if (!iface) {
		usage(argv[0]);
	}
}

static void print_mac(unsigned char *mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void build_eth_hdr
(
	unsigned char* buf,
	const unsigned char dest_mac[6],
	const unsigned char src_mac[6],
	uint16_t ethertype
)
{
	memcpy(buf + 0, dest_mac, 6);
	memcpy(buf + 6, src_mac, 6);

	uint16_t proto_n = htons(ethertype);
	memcpy(buf + 12, &proto_n, sizeof(proto_n));
}

static void build_arp_payload_request
(
	unsigned char* payload_buf,
	const unsigned char src_mac[6],
	uint32_t src_ip_n,
	uint32_t target_ip_n
)
{
	struct arp_hdr a;
	a.htype = htons(ARPHRD_ETHER);
	a.ptype = htons(ETH_P_IP);
	a.hlen = 6;
	a.plen = 4;
	a.opcode = htons(ARPOP_REQUEST);

	memcpy(a.sha, src_mac, 6);
	memcpy(a.spa, &src_ip_n, 4);
	memset(a.tha, 0x00, 6);
	memcpy(a.tpa, &target_ip_n, 4);
	memcpy(payload_buf, &a, sizeof(a));
}

static size_t build_arp_request
(
	unsigned char* frame_buf,
	const unsigned char src_mac[6],
	uint32_t src_ip_n,
	uint32_t target_ip_n
)
{
	unsigned char dest_broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	build_eth_hdr(frame_buf, dest_broadcast, src_mac, ETH_P_ARP);

	unsigned char* payload = frame_buf + sizeof(struct ethhdr);
	build_arp_payload_request(payload, src_mac, src_ip_n, target_ip_n);

	return sizeof(struct ethhdr) + sizeof(struct arp_hdr);
}

int main(int argc, char* argv[]) {
	if (geteuid() != 0) {
		fprintf(stderr, "This program requires root privileges.\n");

		return 1;
	}
	
	if (argc < 2) {
		usage(argv[0]);
		
		return 1;
	}

	char* iface = NULL;
	char* subnet = NULL;

	parse_args(argc, argv, &iface, &subnet);

	netinfo net;
	get_hosts(subnet, &net);

	printf("Target: %s\n", subnet);
	printf("Network: "); print_ip_host(net.network); printf("\n");
	printf("Broadcast: "); print_ip_host(net.broadcast); printf("\n");
	printf("First host: "); print_ip_host(net.first); printf("\n");
	printf("Last host: "); print_ip_host(net.last); printf("\n");
	printf("Hosts: %" PRIu64 "\n", net.n_hosts);

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);

	int ctl = socket(AF_INET, SOCK_DGRAM, 0);

	if (ctl < 0) {
		perror("socket");

		exit(1);
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(ctl, SIOCGIFINDEX, &ifr) < 0) {
		perror("SIOCGIFINDEX");
		close(ctl);
		return 1;
	}

	int ifindex = ifr.ifr_ifindex;

	if (ioctl(ctl, SIOCGIFFLAGS, &ifr) < 0) {
		perror("SIOCGIFFLAGS");
		close(ctl);

		return 1;
	}

	if (!(ifr.ifr_flags & IFF_UP)) {
		fprintf(stderr, "interface is not UP\n");
		exit(1);
	}

	if (ioctl(ctl, SIOCGIFHWADDR, &ifr) < 0) {
		perror("SIOCGIFHWADDR");
		close(ctl);

		return 1;
	}

	unsigned char mac[6];
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	if (ioctl(ctl, SIOCGIFADDR, &ifr) < 0) {
		perror("SIOCGIFADDR");
		close(ctl);

		return 1;
	}

	struct sockaddr_in* sin = (struct sockaddr_in*) &ifr.ifr_addr;
	char ip_str[INET_ADDRSTRLEN];

	if (!inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str))) {
		perror("inet_ntop");
		return 1;
	}

	uint32_t ip_n;
	inet_pton(AF_INET, ip_str, &ip_n);

	close(ctl);

	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

	if (sockfd < 0) {
		perror("socket");

		return 1;
	}

	struct sockaddr_ll sll_bind;
	memset(&sll_bind, 0, sizeof(sll_bind));
	sll_bind.sll_family = AF_PACKET;
	sll_bind.sll_ifindex = ifindex;
	sll_bind.sll_protocol = htons(ETH_P_ARP);

	if (bind(sockfd, (struct sockaddr*) &sll_bind, sizeof(sll_bind)) < 0) {
		perror("bind");
		close(sockfd);

		return 1;
	}

	struct packet_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	
	// placing the interface in question into PROMISC mode.
	// which means that the interface will no longer discard
	// frames that do not have its MAC address as destination
	if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		perror("setsockopt");
	}

	struct target* targets = calloc((size_t) net.n_hosts, sizeof(struct target));

	if (!targets) {
		perror("calloc");
		close(sockfd);

		return 1;
	}

	for (uint64_t i = 0; i < net.n_hosts; i++) {
		targets[i].ip_host = net.first + (uint32_t) i;
		targets[i].replied = false;
		targets[i].sent_ts_ms = 0;
		targets[i].rtt_ms = 0;
	}

	printf("Interface: %s\n", iface);
	printf("MAC: "); print_mac(mac); printf("\n");
	printf("IP: %s\n", ip_str);


	struct sockaddr_ll sll_out;
	memset(&sll_out, 0, sizeof(sll_out));
	sll_out.sll_family = AF_PACKET;
	sll_out.sll_ifindex = ifindex;
	sll_out.sll_halen = ETH_ALEN;
	memset(sll_out.sll_addr, 0xff, ETH_ALEN);

	printf("\n --- Sending ARP requests to %" PRIu64 " hosts... ---\n", net.n_hosts);
	
	// send one, then get some sleep
	for (uint64_t i = 0; i < net.n_hosts && !do_exit; i++) {
		unsigned char frame[1500];

		uint32_t target_host = targets[i].ip_host;
		uint32_t target_n = htonl(target_host);
		size_t flen = build_arp_request(frame, mac, ip_n, target_n);
		ssize_t sent = sendto(sockfd, frame, flen, 0,
			(struct sockaddr*) &sll_out, sizeof(sll_out));

		if (sent != (ssize_t) flen) {
			if (sent < 0) {
				perror("sendto");
			} else {
				fprintf(stderr, "partial send: %zd/%zu\n", sent, flen);
			} 
		} else {
			targets[i].sent_ts_ms = now_ms();
		}

		if (i + 1 < net.n_hosts) {
			usleep(SEND_USLEEP);
		}
	}

	struct pollfd pfd;
	pfd.fd = sockfd;
	pfd.events = POLLIN;

	size_t pending = (size_t) net.n_hosts;
	unsigned char buf[RECV_BUF_SIZE];

	while (!do_exit && pending > 0) {
	    uint64_t now = now_ms();

	    int ret = poll(&pfd, 1, POLL_TIMEOUT_MS);
	    if (ret < 0) {
	        if (errno == EINTR)
	            continue;
	        perror("poll");
	        break;
	    }

	    for (size_t i = 0; i < (size_t) net.n_hosts; i++) {
	        if (!targets[i].replied && targets[i].sent_ts_ms > 0) {
	            uint64_t deadline = targets[i].sent_ts_ms + REPLY_TIMEOUT_MS;
	            if (now >= deadline) {
	                targets[i].sent_ts_ms = 0;
	                pending--;
	            }
	        }
	    }

	    if (!(pfd.revents & POLLIN))
	        continue;

	    struct sockaddr_ll raddr;
	    socklen_t rlen = sizeof(raddr);
	    ssize_t len = recvfrom(sockfd, buf, sizeof(buf), 0,
	                           (struct sockaddr*) &raddr, &rlen);

	    if (len < 0) {
	        if (errno == EINTR)
	            continue;
	        perror("recvfrom");
	        break;
	    }

	    if ((size_t) len < sizeof(struct ethhdr) + sizeof(struct arp_hdr))
	        continue;

	    struct ethhdr* eth = (struct ethhdr*) buf;
	    if (ntohs(eth->h_proto) != ETH_P_ARP)
	        continue;

	    unsigned char* arp_ptr = buf + sizeof(struct ethhdr);
	    struct arp_hdr arp;
	    memcpy(&arp, arp_ptr, sizeof(arp));

	    uint16_t opcode = ntohs(arp.opcode);
	    if (opcode != ARPOP_REPLY)
	        continue;

	    uint32_t spa_n;
	    memcpy(&spa_n, arp.spa, 4);
	    uint32_t spa_host = ntohl(spa_n);

	    if (spa_host < net.first || spa_host > net.last)
	        continue;

	    size_t idx = (size_t)(spa_host - net.first);
	    if (idx >= (size_t)net.n_hosts) {
	        fprintf(stderr, "[WARN] idx out of range: %zu (spa=%u)\n", idx, spa_host);
	        continue;
	    }

	    if (!targets[idx].replied && targets[idx].sent_ts_ms > 0) {
	        uint64_t rtt = now - targets[idx].sent_ts_ms;
	        targets[idx].replied = true;
	        targets[idx].rtt_ms = rtt;
	        memcpy(targets[idx].mac, arp.sha, 6);
	        pending--;
	    }

	    usleep(1000);
	}


	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	setsockopt(sockfd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

	printf("\nResults:\n");
	char ipbuf[INET_ADDRSTRLEN];

	for (size_t i = 0; i < (size_t) net.n_hosts; i++) {
		ip_host_to_str(targets[i].ip_host, ipbuf, sizeof(ipbuf));

		if (targets[i].replied) {
			printf("%s\t", ipbuf);
			print_mac(targets[i].mac);
			printf("\t%3" PRIu64 " ms\n", (uint64_t) targets[i].rtt_ms);
		} else {
			printf("%s\t(no reply)\n", ipbuf);
		}
	}

	free(targets);
	close(sockfd);

	return 0;
}