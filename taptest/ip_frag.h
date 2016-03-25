#ifndef IP_FRAG_H_
# define IP_FRAG_H_

#include <time.h>

#include "ip.h"

#define IP_FRAG_EXPIRE_TIMER 15

struct ip_frag_bufid
{
  unsigned char src_addr[4];
  unsigned char dst_addr[4];
  unsigned char proto;
  unsigned short id;
};

struct ip_frag_table_entry
{
  struct ip_frag_bufid bufid;
  unsigned short dlen;
  time_t expires;
  unsigned char hbuf[60];
  unsigned char dbuf[65536];
  unsigned char rcvbt[65536 / 8];
  struct ip_frag_table_entry *next;
};

void ip_frag_init(void);
void ip_frag_dump(void);
void ip_frag_flush_expired(void);
void ip_frag_flush_bufid(struct ip_frag_bufid *bufid);
struct ip_frag_table_entry *ip_frag_find_bufid(struct ip_frag_bufid *bufid);
struct ip_frag_table_entry *ip_frag_new_element(struct ip_frag_bufid *bufid);
void ip_frag_handle(struct ip_hdr *pkt, struct ip_frag_bufid *bufid);

#endif /* IP_FRAG_H_ */
