#ifndef ICMP_H_
# define ICMP_H_

#define ICMP_TYPE_REPLY		0
#define ICMP_TYPE_REQUEST	8

struct icmp_hdr
{
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short id;
  unsigned short sequence;
  unsigned char padding[];
} __attribute__((packed));

unsigned short icmp_compute_checksum(void *data, unsigned short len);
void icmp_send_reply(unsigned char *to, unsigned char *payload,
		     unsigned short len, unsigned short id, unsigned short sequence);
void icmp_handle(unsigned char *src_ip, unsigned char *data, unsigned short len);

#endif /* ICMP_H_ */
