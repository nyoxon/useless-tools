/*
* arp_repair.c - repairs caches after ARP poisoning
* usage: ./arp_repair <iface> <victim_ip> <gateway_ip>
*
* Sends N unicast replies containing the correct bindings to both sides. 
* Build: gcc -Wall -O2 -o arp_repair arp_repair.c
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>

#define ETH_P_ARP 0x0806

struct arp_packet {
	struct ethhdr eth;
	uint16_t htype, ptype;
	uint8_t  hlen, plen;
	uint16_t opcode;
	uint8_t  sender_mac[6];
	uint8_t  sender_ip[4];
	uint8_t  target_mac[6];
	uint8_t  target_ip[4];
} __attribute__((packed));

static void hex_to_mac(const char* s, uint8_t* m) {
	sscanf(s, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
	       &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
}

static void send_reply(int sock, struct sockaddr_ll* sa,
                       const uint8_t* my_mac, const char* ip_str,
                       const uint8_t* dst_mac, const char* dst_ip_str)
{
	struct arp_packet pkt;
	uint8_t ip[4], dst_ip[4];

	inet_pton(AF_INET, ip_str, ip);
	inet_pton(AF_INET, dst_ip_str, dst_ip);

	memset(&pkt, 0, sizeof(pkt));
	memcpy(pkt.eth.h_dest, dst_mac, 6);
	memcpy(pkt.eth.h_source, my_mac, 6);
	pkt.eth.h_proto = htons(ETH_P_ARP);
	pkt.htype  = htons(ARPHRD_ETHER);
	pkt.ptype  = htons(ETH_P_IP);
	pkt.hlen   = 6;
	pkt.plen   = 4;
	pkt.opcode = htons(ARPOP_REPLY);
	memcpy(pkt.sender_mac, my_mac, 6);      /* who sents */
	memcpy(pkt.sender_ip, ip, 4);
	memcpy(pkt.target_mac, dst_mac, 6);
	memcpy(pkt.target_ip, dst_ip, 4);

	sa->sll_halen = 6;
	memcpy(sa->sll_addr, dst_mac, 6);
	sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)sa, sizeof(*sa));
}

int main(int argc, char** argv)
{
	if (argc != 4) {
		fprintf(stderr, "usage: %s <iface> <victim_ip> <gateway_ip>\n", argv[0]);
		return 1;
	}

	/* ACTUAL MACs passed via env: VICTIM_MAC and GW_MAC */
	const char* v = getenv("VICTIM_MAC");
	const char* g = getenv("GW_MAC");
	if (!v || !g) {
		fprintf(stderr, "set VICTIM_MAC=xx:xx:xx:xx:xx:xx GW_MAC=xx:xx:xx:xx:xx:xx\n");
		return 1;
	}

	uint8_t victim_mac[6], gw_mac[6], my_mac[6];
	hex_to_mac(v, victim_mac);
	hex_to_mac(g, gw_mac);

	/* our MAC: retrieved from the interface (for a valid source eth address) */
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);

	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family   = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ARP);
	sa.sll_ifindex  = if_nametoindex(argv[1]);
	sa.sll_hatype   = ARPHRD_ETHER;
	bind(sock, (struct sockaddr*)&sa, sizeof(sa));

	/*
	* eth src / sender_mac: use the REAL MAC address of the IP owner, not our own. 
	* This way, the victim receives the reply "as if it were from the gateway"
	* and immediately accepts the correct binding. 
	*/
	for (int i = 0; i < 5; i++) {
		/* victim: "the gateway <gw_ip> is-at <actual MAC of the gateway>" */
		send_reply(sock, &sa, gw_mac,     argv[3], victim_mac, argv[2]);
		/* gateway: "the victim <victim_ip> is at <victim's real MAC>" */
		send_reply(sock, &sa, victim_mac, argv[2], gw_mac,     argv[3]);
		usleep(200000);
	}

	printf("[+] repair replies sent (5x)\n");
	return 0;
}