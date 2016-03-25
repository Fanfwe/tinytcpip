#ifndef IP_H_
# define IP_H_

#include "ip_frag.h"

#define IP_PROTO_ICMP		1
#define IP_PROTO_TCP		6
#define IP_PROTO_UDP		17

struct ip_hdr
{
  unsigned int hlen:4;
  unsigned int version:4;
  unsigned char tos;
  unsigned short len;
  unsigned short id;
  unsigned short frag_offset;
  unsigned char ttl;
  unsigned char proto;
  unsigned short chksum;
  unsigned char src_addr[4];
  unsigned char dst_addr[4];
  unsigned char opt[];
} __attribute__((packed));

extern unsigned char ip_address[];
extern unsigned char ip_addr_any[];

void ip_init(void);
unsigned short ip_compute_checksum(void *data, unsigned short len);
void ip_send_packet(unsigned char *to, unsigned char proto, unsigned char tos,
		    unsigned char *payload, unsigned short len, unsigned int nofrag);
void ip_handle(unsigned char *src_mac, unsigned char *data, unsigned short len);
void ip_deliver_packet(struct ip_hdr *pkt);

#endif /* IP_H_ */
