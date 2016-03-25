#ifndef ETHER_H_
# define ETHER_H_

#define ETHER_TYPE_IPV4		0x0800
#define ETHER_TYPE_ARP		0x0806

struct ether_hdr
{
  unsigned char dst_mac[6];
  unsigned char src_mac[6];
  unsigned short type;
  unsigned char payload[];
} __attribute__((packed));

void ether_send_frame(unsigned char *to, unsigned short type,
		      unsigned char *payload, unsigned short size);
void ether_recv_frame(void);
int ether_can_recv();

#endif /* ETHER_H_ */
