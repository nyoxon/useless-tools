// a DNS-query software that uses DNS internally (brutal)
// however, it is a reasonable piece of code for
// understanding the internal structure of DNS

// uselessness = 5/10

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

// lmao
void high_level(const char* host_name) {
	/*resolving host-name to ip addres via getaddrinfo*/

	if (!host_name) {
		return;
	}

	struct addrinfo hints = {0}, *res;
	hints.ai_family = AF_INET;

	int err = getaddrinfo(host_name, NULL, &hints, &res);

	if (err != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		return;
	}

	struct sockaddr_in *addr = (struct sockaddr_in*) res->ai_addr;
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));

	// printf("getaddrinfo: %s\n", ip);

	freeaddrinfo(res);	
}



/* --------------------------- */

/*

[DNS PACKET]

| - header - 12 bytes - |
| - question - |
| - answer -|
| - authority -|
| - additional -|

query simples usa apenas header e question

[QUESTION SECTION]

| - QNAME - |
| - QTYPE - 2 bytes |
| - QCLASS - 2 bytes |

QNAME = sequência de labels

' exemplo:
domain = example.com

QNAME = 7 e x a m p l e 3 c o m 0
onde o 0 final indica que qname terminou
				'


QTYPE = A (IPV4) AAAA (IPV6) 15 (MX) 16 (TXT)
QCLASS = 1 (INTERNET)


[ENVIO DO PACOTE]

geralmente client usa UDP com buffer de 512 bytes
geralmente server usa porta 53

fluxo:

- cliente monta header e question
- sendto() para o server DNS
- cliente espera
- cliente confere se ID bate e se outras flags de interesse
foram satisfeitas onde server envia um 'answer'

[ANSWER (RR ou Resource Record) SECTION]

| - NAME - 2 bytes|
| - TYPE - 2 bytes|
| - CLASS - 2 bytes|
| - TTL - 4 bytes|
| - RDLENGTH - 2 bytes|
| - RDATA - RDLENGTH bytes|

NAME = ponteiro comprimido*
TYPE = se espera que seja o tipo de question
CLASS = o mesmo de TYPE
TTL = tempo de cache (300 = 5min)
RDLENGTH = tamanho do dado
RDATA = dado


NAME E COMPRESSÃO DE PONTEIRO

name é uma label:
03 'w' 'w' 'w'
06 'g' 'o' 'o' 'g' 'l' 'e'
etc
00

name comprimido fica:
03 'w' 'w' 'w'
C0 0C (=11000000 00001100 onde os 2 bits mais altos (11) marca um pointer
e os restantes é um offset a partir do inicio do pacote)

C0 0C -> offset 12


TYPE =
A -> RDLENGTH = 4 bytes
AAAA -> RDLENGTH = 16 bytes


MX (mail exchange) -> | preference (2 bytes) + exchange (variavel) |
preference é a prioridade do servidor. quanto menor, maior a prioridade.
exchange é o domain name, nome do host que recebe o email

geralmente é usado junto com o SMTP; fluxo de uso SMTP:
- quer mandar email para user@google.com
- MX google.com
- ordena os MX por preference
- tenta conectar via SMTP no exchange
- se falhar, tenta o proximo MX
- se nao existir MX: fallback para A / AAAA (exceto NULL MX)


CNAME (Canonical Name) -> | NAME |
name indica o nome canonico para o qual o alias aponta
blog.example.com -> CNAME -> example-blog.herokuapp.com
se alguem pedir a resolução de blog.example.com, o servidor
DNS vai responder que esse dominio é um alias para
example-blog.herokuapp.com
ao enviar um CNAME, a resposta pode ter três caras:
o tipo da mensagem é NS: o server nao sabe a resposta, mas sabe quem sabe
o tipo da mensagem é SOA: o server é autoritario e nao existe CNAME
o tipo da mensagem é CNAME: existe um alias e o server conhece ele



NS (Name Server) -> | NAME |
name indica quais servidores são autoritarios para um dominio ou zona
"quem sabe tudo sobre o dominio?"



SOA (Start of Authority) -> |  MNAME | RNAME | SERIAL | REFRESH | RETRY | EXPIRE | MINIMUM |
ver a struct dns_soa_fixed para informações sobre cada campo


PTR (Pointer ou reverse DNS) -> | NAME |
dado um ip, saber o dominio
o qname da question deve ser modificado de acordo
com a função ip_to_reverse_qname

| AUTHORITY SECTION |
mesma coisa que o answer

[O QUE ESPERAR COMO RESPOSTA]

- answer e question com ID's iguais
- QR = 1
- RCODE = 0
- ANCOUNT >= 1
- TYPE coerente com QTYPE
- RDLENGTH compatível

*/

#define DNS_QR		0x8000 // (1 << 15)
#define DNS_AA		0x0400 // (1 << 10)
#define DNS_TC		0x0200 // (1 << 9)
#define DNS_RD 		0x0100 // (1 << 8)
#define DNS_RA  	0x0080 // (1 << 7)
#define DNS_AD  	0x0020 // (1 << 6)
#define DNS_CD  	0x0010 // (1 << 5)
// #define DNS_OPCODE_SHIFT 11 // (flags >> DNS_OPCODE_SHIFT) & 0x0F
// #define DNS_RCODE_MASK	 0x000F // = 15 (flags & DNS_RCODE_MASK)

#define RR_NAME_MASK 0xC0

#define QCLASS_IN 1

#define QTYPE_A 1
#define QTYPE_A_LENGTH 4

#define QTYPE_AAAA 28
#define QTYPE_AAAA_LENGTH 16

#define QTYPE_MX 15
#define QTYPE_MX_PREFERENCE_LENGTH 2

#define QTYPE_CNAME 5
#define QTYPE_NS 2
#define QTYPE_SOA 6
#define QTYPE_PTR 12

struct dns_header {
	uint16_t id; // número aleatório escolhido pelo cliente
	/*aparentemente querys modernos usam numeros aleatorios
	como id para evitar spoofing*/
	uint16_t flags;
	/*

	15  14  13  12  11  10    9    8    7   6   5     4   3  2  1  0
	QR | 	OPCODE 	  | AA | TC | RD | RA | Z |	AD | CD | 	RCODE   |

	*/
	/* 
	QR = 0 (query) | 1 (response) 
	OPCODE = 0000 (query padrão) | 0001 inverse query | 0002 status
	AA = 1 (server é autoridade pelo dominio) | 
	TC = 1 (truncado) geralmente cliente refaz a query usando TCP
	RD = 1 (pede recursão) | 0 (server só responde se souber)
	RA = 1 (server suporta recursão)
	Z (sempre deve ser zero) 
	AD = 1 (autenticação com criptografia DNSSEC)
	CD = 1 (cliente diz nao valide assinaturas)
	RCODE = 0 (OK) | 1 (format error) | 2 (server failure) |
	3 (name error) | 4 (not implemented) | 5 (refused)
	*/
	uint16_t qdcount; // número de entradas em question section
	uint16_t ancount; // número de registros em answer section
	uint16_t nscount; // número de registros em authority section
	uint16_t arcount; // número de registros adicionais
};

void print_dns_header_flags(uint16_t flags) {
	for (int i = 15; i >= 0; i--) {
		unsigned char bit = (flags & (1u << i)) ? '1' : '0';

		if (i == 15) {
			printf("QR=%c ", bit);
			continue;
		}

		if (i < 15 && i >= 11) {
			if (i == 14) {
				printf("OPCODE=");
			}

			printf("%c", bit);
			
			if (i == 11) {
				printf(" ");
			}

			continue;
		}

		if (i == 10) {
			printf("AA=%c ", bit);
			continue;
		}

		if (i == 9) {
			printf("TC=%c ", bit);
			continue;
		}

		if (i == 8) {
			printf("RD=%c ", bit);
			continue;
		}

		if (i == 7) {
			printf("RA=%c ", bit);
			continue;
		}

		if (i == 6) {
			printf("Z=%c ", bit);
			continue;
		}

		if (i == 5) {
			printf("AD=%c ", bit);
			continue;
		}

		if (i == 4) {
			printf("CD=%c ", bit);
			continue;
		}

		if (i == 3) {
			printf("RCODE:");
		}

		printf("%c", bit);

		if (i == 0) {
			printf("\n");
		}
	}
}

void print_dns_header(const struct dns_header* dns) {
	printf(" --- DNS HEADER ---\n");
	printf("ID: %x\n", ntohs(dns->id));
	print_dns_header_flags(ntohs(dns->flags));
	printf("qdcount: %d\n", ntohs(dns->qdcount));
	printf("ancount: %d\n", ntohs(dns->ancount));
	printf("nscount: %d\n", ntohs(dns->nscount));
	printf("arcount: %d\n\n", ntohs(dns->arcount));
}

/*
BITWISE OPERATORS

~ -> not
~1 = 0
~0 = 1

| -> or
1 | 1 = 1
1 | 0 = 1
0 | 0 = 0
(ativa bits)

ex:
uint16_t flags = 0 ou 0000 0000 0000 0000
flags |= DNS_RD (0x0100 ou 0000 0001 0000 0000) = 0000 0001 0000 0000


& -> and
1 & 1 = 1
1 & 0 = 0
0 & 0 = 0
(testa ou desativa bits)

(flags & DNS_RD testa se o bit DNS_RD de flags está ativo)
flags = 1000 1011 0000 1000
DNS_RD = 0000 0001 0000 0000
flags & DNS_RD = 0000 0001 0000 0000 != 0

flags = 1000 1010 0000 1000
flags & DNS_RD = 0000 0000 0000 0000 == 0

(exemplo desativando bits)
flags = 1000 1011 0000 1000
flags &= ~DNS_RD = 1000 1011 0000 1000 & 1111 1110 1111 1111 =
= 1000 1010 0000 1000 (DNS_RD bit é desativado)


^ -> xor (exclusive or / ou um ou outro)
1 ^ 1 = 0
1 ^ 0 = 1
0 ^ 0 = 0
(alterna bits / se estava ativo, fica desativo e vice-versa)

flags = 1000 1011 0000 1000
flags ^= DNS_RD = 1000 1011 0000 1000 ^ 0000 0001 0000 0000 =
= 1011 1010 0000 1000

<< -> left shift (A << B)
avança em B "casas" todos os bits de A colocando 0's nos bits da direita
caso necessário
uint16_t mask = 1 (0000 0000 0000 0001)
mask = mask << 8 = 100 (0000 0001 0000 0000)
1 << 8 = 0x0100 = DNS_RD

unsigned char a = 21 (0001 0101)
a = a << 1 = 42 (0010 1010)

>> -> right shift (A >> B)
regressa em B "casas" todos os bits de A colocando 0's nos bits da esquerda
caso necessário

unsigned char a = 21 (0001 0101)
a = a >> 2 = 5 (0000 0101)
(serve para extrait valores)

uint16_t opcode = (flags >> DNS_OPCODE_SHIFT) & mask;
flags = 0101 0001 0010 0010
flags >> DNS_OPCODE_SHIFT (11) = 0000 0000 0000 1010 (os
unicos bits ativos são o do opcode)
(flags >> DNS_OPCODE_SHIFT) & 0xF = 
0000 0000 0000 1010 & mask = 0000 0000 0000 mascaradogamer

exemplo sinistro em DNS:
RD = 1 (bit 8)
QR = 0 (bit 15)
OPCODE = 0

(definindo flags)

uint16_t flags = 0;
flags |= 1 << 8;

(lendo flags)

uint16_t flags = ntohs(header.flags);

if (flags & (1 << 15)) {
	// é resposta
}

uint16_t rcode = flags & 0x000F;

*/

struct dns_question {
	uint16_t qtype;
	uint16_t qclass;
}__attribute__((packed));

int resolve_qtype(char* type, uint16_t* out) {
	if (strcasecmp(type, "A") == 0) {
		*out = QTYPE_A;
	} else if (strcasecmp(type, "AAAA") == 0) {
		*out = QTYPE_AAAA;
	} else if (strcasecmp(type, "MX") == 0) {
		*out = QTYPE_MX;
	} else if (strcasecmp(type, "CNAME") == 0) {
		*out = QTYPE_CNAME;
	} else if (strcasecmp(type, "NS") == 0) {
		*out = QTYPE_NS;
	} else if (strcasecmp(type, "PTR") == 0) {
		*out = QTYPE_PTR;
	} else if (strcasecmp(type, "SOA") == 0) {
		*out = QTYPE_SOA;
	} else {
		return -1;
	}

	return 0;
}

void print_dns_question(const struct dns_question* q, char* qname) {
	char type[128];
	printf(" --- QUESTION ---\n");

	printf("qname: %s\n", qname);
	printf("qtype: %u\n", q->qtype);
	printf("qclass: %u\n\n", q->qclass);
}

struct dns_rr_fixed {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlen;
}__attribute__((packed));

void print_dns_rr_fixed(const struct dns_rr_fixed* rr) {
	printf(" --- RR ---\n");
	printf("type: %u\n", rr->type);
	printf("class: %u\n", rr->class);
	printf("ttl: %d\n", rr->ttl);
	printf("rdlen: %u\n", rr->rdlen);
}

/*
como parseiar o DNS:

while (rrs-) {
	parse_name();
	read_fixed_rr();
	parse_rdata();
}
*/

struct dns_soa_fixed {
	// char* mname -> servidor primario
	// char* rname -> email do administrador
	uint32_t serial; // numero de seria da zona
	uint32_t refresh; // tempo para atualizar registros
	uint32_t retry; // tempo para tentar novamente
	uint32_t expire; // tempo para expirar a zona
	uint32_t minimum; // ttl minimo para registros na zona
}__attribute__((packed));

void print_dns_soa_fixed(const struct dns_soa_fixed* soa) {
	printf("serial: %d\n", ntohl(soa->serial));
	printf("refresh: %d\n", soa->refresh);
	printf("retry: %d\n", soa->retry);
	printf("expire: %d\n", soa->expire);
	printf("minimum: %d\n", soa->minimum);
}

static size_t domain_to_unmasked_label(const char* domain, unsigned char* out) {
	/*
	transforma uma string
	em labels
	*/

	// domain = "example.com"
	size_t len = 0;
	const char* start = domain;

	while(*start) {
		// 1º it; 
		// start -> 'e'
		const char* end = start;
		// end -> 'e'

		while (*end && *end != '.') {
			/*conta quantos caracteres existem até o proximo
			. ou \0*/
			end++;
		}

		// end -> '.'

		size_t label_len = end - start;
		// label_len = 7

		out[len++] = (unsigned char) label_len;
		// out[0] = 7

		memcpy(out + len, start, label_len);
		// out[0-8] = 7 'e' 'x' 'a' 'm' 'p' 'l' 'e'
		len += label_len;

		if (*end == '.') {
			start = end + 1;
		} else {
			break;
		}
	}

	out[len++] = 0;
	return len;
}

static void rr_parse_name(unsigned char** ptr) {
    if ((**ptr & RR_NAME_MASK) == RR_NAME_MASK) {
        *ptr += 2;
        return;
    }

    while (**ptr != 0) {
        *ptr += **ptr + 1;
    }
    (*ptr)++;
}

static void rr_read_fixed(unsigned char** ptr, struct dns_rr_fixed* rr) {
	rr_parse_name(ptr);
	/*pula NAME*/
	/*ptr agora está em TYPE*/
	memcpy(rr, *ptr, sizeof(*rr));
	*ptr += sizeof(*rr);

	rr->type = ntohs(rr->type);
	rr->class = ntohs(rr->class);
	rr->ttl = ntohl(rr->ttl);
	rr->rdlen = ntohs(rr->rdlen);
}

static void qr_read_question(unsigned char** ptr, struct dns_question* q) {
	while (**ptr != 0) {
		*ptr += **ptr + 1;
	}

	(*ptr)++;

	if (q) {
		memcpy(q, *ptr, sizeof(*q));
	}

	*ptr += 4;
}

int connect_to_dns_server(const char* server, struct sockaddr_in* dns) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	inet_pton(AF_INET, server, &dns->sin_addr);

	return sock;
}

void create_dns_header
(
	struct dns_header** hdr,
	uint16_t id,
	uint16_t flags,
	uint16_t qdcount
) 
{
	(*hdr)->id = htons(id);
	(*hdr)->flags = htons(flags);
	(*hdr)->qdcount = htons(qdcount);
	(*hdr)->ancount = htons(0);
	(*hdr)->nscount = htons(0);
	(*hdr)->arcount = htons(0);
}

int ip_to_reverse_qname(char* ip, char* out, size_t out_len) {
	struct in_addr ipv4;
	struct in6_addr ipv6;

	/*
	se for ipv4, invertemos os bytes do ip e colocamos
	".in-addr.arpa" no fim

	se for ipv6, você
	- expande o endereço
	- converte para hexadecimal
	- separa cada nibble (4 bits)
	- inverte tudo
	- coloca "ip6.arpa" no fim

	*/

	if (inet_pton(AF_INET, ip, &ipv4) == 1) {
		unsigned char* b = (unsigned char*) &ipv4;

		int n = snprintf
		(
			out, out_len,
			"%u.%u.%u.%u.in-addr.arpa",
			b[3], b[2], b[1], b[0]
		);

		return (n < 0 || (size_t) n >= out_len) ? -1 : 0;
	}

	if (inet_pton(AF_INET6, ip, &ipv6) == 1) {
		char* p = out;
		size_t remaining = out_len;

		for (int i = 15; i >= 0; i--) {
			unsigned char byte = ipv6.s6_addr[i];

			unsigned char low = byte & 0x0F;
			unsigned char high = (byte >> 4) & 0x0F;

			int n = snprintf(p, remaining, "%x.%x.", low, high);

			if (n < 0 || (size_t) n >= remaining) {
				return -1;
			}

			p += n;
			remaining -= n;
		}

		int n = snprintf(p, remaining, "ip6.arpa");
		return (n < 0 || (size_t) n >= remaining) ? -1 : 0;
	}

	return -1;
}

size_t create_question
(
	struct dns_question* q,
	unsigned char* packet,
	char* host_name
)
{
	if (q->qtype == QTYPE_PTR) {
		size_t max_length = 256;
		unsigned char* tmp = host_name;

		int n = ip_to_reverse_qname(host_name, tmp, max_length);

		if (n < 0) {
			fprintf(stderr, "failed to parse QNAME on question with QTYPE=PTR\n");
			exit(1);
		}

		host_name = tmp;
	}

	size_t qname_len = domain_to_unmasked_label(host_name, packet);

    unsigned char *qinfo = packet + qname_len;
    *(uint16_t *)qinfo = htons(q->qtype);      // QTYPE A
    *(uint16_t *)(qinfo + 2) = htons(q->qclass); // QCLASS IN

    size_t packet_size = sizeof(struct dns_header) +
                          qname_len + 4;

    return packet_size;
}

uint16_t qtype_to_rdlength(uint16_t qtype) {
	if (qtype == QTYPE_A) {
		return QTYPE_A_LENGTH;
	} else if (qtype == QTYPE_AAAA) {
		return QTYPE_AAAA_LENGTH;
	}
}

void print_ipv4(const uint8_t *rdata) {
	char buf[INET_ADDRSTRLEN];

	if (!inet_ntop(AF_INET, rdata, buf, sizeof(buf))) {
		perror("inet_ntop");
		return;
	}

	printf("%s\n", buf);
}

void print_ipv6(const uint8_t *rdata) {
	char buf[INET6_ADDRSTRLEN];

	if (!inet_ntop(AF_INET6, rdata, buf, sizeof(buf))) {
		perror("inet_ntop");
		return;
	}

	printf("%s\n", buf);
}

int dns_read_name
(
	unsigned char *base, // inicio da mensagem DNS
    unsigned char *ptr, // onde o nome começa (NAME, RDATA, etc)
    char *out, // onde o nome legivel será escrito
    size_t out_len,
    size_t *consumed) // quantos bytes o nome ocupou no local original
{
    size_t out_pos = 0; // onde escrever em out
    size_t jumped = 0; // se já seguimos um ponteiro
    size_t used = 0; // quantos bytes o nome ocupou no local original

    while (1) {
        unsigned char len = *ptr;

        // ponteiro de compressão
        if ((len & 0xC0) == 0xC0) {
            uint16_t offset = ((len & 0x3F) << 8) | *(ptr + 1);
            /*
			len & 0x3F remove os dois bits mais altos 11
			portanto agora existem 14 bits consideraveis:
			11xxxxxx xxxxxxxx
			xxxxxx -> parte alta
			xxxxxxxx -> parte baixa

			len & 0x3F = parte alta
			=> (len & Ox3F) << 8 = xxxxxx 00000000

			*(ptr + 1) -> segundo bit da máscara (se for
			C0 0C, len será 0xC0 e *(ptr + 1) será 0x0C (12 em decimal))

			=> parte baixa = 0x0C = 00000000 00001100

			=> ((len & 0x3F) << 8) | *(ptr + 1) =
			xxxxxx 00000000 | 000000 00001100 = 
			xxxxxx 00001100 (no caso do C0 0C, a parte alta vai ser igual a 0,
			portanto offset = 12.)

			exemplo com mascara C1 (1100 0001) 2A (0010 1010):
			(C1 & 3F) = 0000 0001
			<< 8  = 0000 0001 0000 0000
			| 2A = 0000 0001 0010 1010 = 298 (aponta para o byte 298
			a partir do começo da mensagem DNS)
			
            */
            ptr = base + offset;

            if (!jumped) used += 2; // não anda mais no local original
            jumped = 1;
            continue;
        }

        // fim do nome
        if (len == 0) {
            if (!jumped) used += 1; // 1 byte só se nao houve ponteiro
            break;
        }

        // label normal

        ptr++;
        if (!jumped) used += len + 1;

        if (out_pos + len + 1 >= out_len)
            return -1;

        memcpy(out + out_pos, ptr, len);
        out_pos += len;
        out[out_pos++] = '.';

        ptr += len;
    }

    if (out_pos == 0)
        out[out_pos++] = '.';

    out[out_pos] = 0;

    if (consumed)
        *consumed = used;

    return 0;
}

void handle_mx
(
	struct dns_rr_fixed* rr, 
	uint8_t** rdata, 
	unsigned char* buf
)
{
	if (rr->rdlen < QTYPE_MX_PREFERENCE_LENGTH) {
		fprintf(stderr, "MX RR preference to small\n");
		return;
	}

	uint16_t preference = ntohs(*(uint16_t*) *rdata);

	char name[256];
	size_t consumed;

	dns_read_name(buf, *rdata + 2, name, sizeof(name), &consumed);

	if (rr->rdlen == 3 && preference == 0 && strcmp(name, "")) {
		printf("MX: NULL (domain does not accept mail)\n");
	} else {
		printf("MX: preference=%u, exchange=%s\n", preference, name);
	}
}

void handle_cname
(
	uint8_t** rdata, 
	unsigned char* buf
)
{
	char name[256];
	size_t consumed;

	dns_read_name(buf, *rdata, name, sizeof(name), &consumed);	
	printf("%s\n", name);
}

void handle_ns
(
	uint8_t** rdata, 
	unsigned char* buf
)
{
	char name[256];
	size_t consumed;

	dns_read_name(buf, *rdata, name, sizeof(name), &consumed);

	printf("%s\n", name);
}

void handle_soa
(
	uint8_t** rdata, 
	unsigned char* buf
)
{
	char mname[256];
	size_t consumed;
	uint8_t* end = *rdata;

	dns_read_name(buf, end, mname, sizeof(mname), &consumed);

	end += consumed;

	char rname[256];
	dns_read_name(buf, end, rname, sizeof(rname), &consumed);
	end += consumed;

	struct dns_soa_fixed soa;
	memcpy(&soa, end, sizeof(soa));

	soa.serial = ntohl(soa.serial);
	soa.refresh = ntohl(soa.refresh);
	soa.retry = ntohl(soa.retry);
	soa.expire = ntohl(soa.expire);
	soa.minimum = ntohl(soa.minimum);

	printf("mname: %s\n", mname);
	printf("rname: %s\n", rname);
	print_dns_soa_fixed(&soa);
}

void handle_ptr
(
	uint8_t** rdata, 
	unsigned char* buf
)
{
	char name[256];
	size_t consumed;

	dns_read_name(buf, *rdata, name, sizeof(name), &consumed);

	printf("%s\n", name);	
}

void handle_answer_type
(
	struct dns_rr_fixed* rr, 
	uint8_t** rdata, 
	unsigned char* buf
) 
{
	if (rr->type == QTYPE_A && rr->rdlen == QTYPE_A_LENGTH) {
		print_ipv4(*rdata);
	} else if (rr->type == QTYPE_AAAA && rr->rdlen == QTYPE_AAAA_LENGTH) {
		print_ipv6(*rdata);
	} else if (rr->type == QTYPE_MX) {
		handle_mx(rr, rdata, buf);
	} else if (rr->type == QTYPE_CNAME) {
		handle_cname(rdata, buf);
	} else if (rr->type == QTYPE_NS) {
		handle_ns(rdata, buf);
	} else if (rr->type == QTYPE_SOA) {
		handle_soa(rdata, buf);
	} else if (rr->type == QTYPE_PTR) {
		handle_ptr(rdata, buf);
	}
}

void udp_query(char* host_name, uint16_t qtype) {
	/*resolving host-name to ip addr via udp query using dns packet*/

	struct sockaddr_in dns = {
		.sin_family = AF_INET,
		.sin_port = htons(53)
	};

	printf(" <<< CONNECTING TO %s:53 >>> \n", host_name);

    int sock = connect_to_dns_server("8.8.8.8", &dns);

    printf(" <<< CONNECTION ESTABLISHED >>> \n");

    unsigned char buf[512] = {0};

    printf(" <<< CREATING DNS HEADER >>> \n\n");

    struct dns_header* hdr = (struct dns_header*) buf;
    uint16_t id = 0x1234;
    uint16_t flags = 0;
    flags |= DNS_RD;
    uint16_t qdcount = 1;
    create_dns_header(&hdr, id, flags, qdcount);
    print_dns_header(hdr);

    printf(" @@@ QUESTION @@@ \n\n");
    printf(" <<< CREATING QUESTION >>> \n\n");

    unsigned char *qname = buf + sizeof(struct dns_header);
    /*aponta para o começo do buffer + sizeof(struct dns_header,
    ou seja, o fim da memoria efetiva para qual hdr aponta*/

    struct dns_question q = {
    	.qtype = qtype,
    	.qclass = QCLASS_IN,
    };

    size_t packet_size = create_question(&q, qname, host_name);
    print_dns_question(&q, host_name);

    printf(" <<< SENDING PACKET >>> \n");

    sendto(sock, buf, packet_size, 0,
           (struct sockaddr *)&dns, sizeof(dns));

    printf(" <<< PACKET HAS BEEN RECEIVED >>> \n\n");

    ssize_t n = recv(sock, buf, sizeof(buf), 0);

    printf(" @@@ ANSWER @@@ \n\n");

    struct dns_header* ans_hdr = (struct dns_header*) buf;
    print_dns_header(ans_hdr);
	unsigned char *ans = buf + sizeof(struct dns_header);

	// pula question e usa apenas answer

	for (int i = 0; i < ntohs(ans_hdr->qdcount); i++) {
		qr_read_question(&ans, NULL);
	}

	for (int i = 0; i < ntohs(ans_hdr->ancount); i++) {
		struct dns_rr_fixed rr;
		rr_read_fixed(&ans, &rr);

		if (rr.type == qtype) {
			print_dns_rr_fixed(&rr);
			handle_answer_type(&rr, &ans, buf);
			printf("\n");

			ans += rr.rdlen;
		} else {
			fprintf(stderr, "qtype or rdlength incompatible\n");
			continue;
		}
	}

	for (int i = 0; i < ntohs(ans_hdr->nscount); i++) {
		struct dns_rr_fixed rr;
		rr_read_fixed(&ans, &rr);

		print_dns_rr_fixed(&rr);
		handle_answer_type(&rr, &ans, buf);
		printf("\n");

		ans += rr.rdlen;
	}

    close(sock);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		fprintf(stderr, "usage: %s [host-name] [qtype]\n", argv[0]);
		fprintf(stderr, "qtype = A (1)-> ipv4 normal dns\n");
		fprintf(stderr, "qtype = AAAA (28) -> ipv6 normal dns\n");
		fprintf(stderr, "qtype = PTR (12)-> reverse dns\n");
		fprintf(stderr, "qtype = CNAME (5) -> canonical name of domain\n");
		fprintf(stderr, "qtype = MX (15) -> you probably won't use and I don't remember its usage\n");
		fprintf(stderr, "qtype = NS (2) -> who is 'resposible' for the domain\n");
		fprintf(stderr, "qtype = SOA (6) -> don't remember\n");
		return 1;
	}

	uint16_t qtype;
	if (resolve_qtype(argv[2], &qtype) < 0) {
		fprintf(stderr, "invalid qtype\n");
		return 1;
	}

	udp_query(argv[1], qtype);

	return 0;
}