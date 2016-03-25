#ifndef ARP_H_
# define ARP_H_

#include <time.h>

#define ARP_OPER_REQUEST	1
#define ARP_OPER_REPLY		2

struct arp_hdr
{
  unsigned short hw_type;
  unsigned short proto_type;
  unsigned char  hw_len;
  unsigned char  proto_len;
  unsigned short oper;
  unsigned char  sha[6];
  unsigned char  spa[4];
  unsigned char  tha[6];
  unsigned char  tpa[4];  
} __attribute__((packed));

struct arp_table_entry
{
  unsigned char ip_addr[4];
  unsigned char mac_addr[6];
  time_t age;
  int present;
};

void arp_init(void);
void arp_table_dump(void);
void arp_table_add(unsigned char *ip_addr, unsigned char *mac_addr);
void arp_resolve(unsigned char *to, unsigned char *dest_arp);
void arp_send_reply(unsigned char *to, unsigned char *sha,
		    unsigned char *spa, unsigned char *tpa);
void arp_handle(unsigned char *src_mac, unsigned char *data,
		unsigned short len);

#endif /* ARP_H_ */
