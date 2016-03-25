#include <stdlib.h>

#include "ip.h"
#include "ether.h"
#include "icmp.h"

int send_fragments()
{

  struct ip_hdr *p1;
  struct ip_hdr *p2;
  struct ip_hdr *p3;
  int i;

  p1 = malloc(1224);
  p2 = malloc(420);
  p3 = malloc(24);

  p1->hlen = 5;
  p1->version = 4;
  p1->tos = 0;
  p1->len = htons(820);
  p1->id = 0;
  p1->frag_offset = htons(0x2000);//MF; Offset=0
  p1->ttl = 42;
  p1->proto = IP_PROTO_ICMP;
  p1->chksum = 0;
  p1->src_addr[0] = 192;
  p1->src_addr[1] = 168;
  p1->src_addr[2] = 0;
  p1->src_addr[3] = 1;
  p1->dst_addr[0] = 192;
  p1->dst_addr[1] = 168;
  p1->dst_addr[2] = 0;
  p1->dst_addr[3] = 2;
  for (i = 0; i < 1204; ++i)
    p1->opt[i] = i;
  struct icmp_hdr *ihdr = &(p1->opt);
  ihdr->type = ICMP_TYPE_REQUEST;
  ihdr->code = 0;
  ihdr->checksum = 0;
  ihdr->id = 0;
  ihdr->sequence = 0;
  ihdr->checksum = icmp_compute_checksum(ihdr, 1204);

  p1->chksum = ip_compute_checksum(p1, sizeof(struct ip_hdr));
  
  p2->hlen = 5;
  p2->version = 4;
  p2->tos = 0;
  p2->len = htons(420);
  p2->id = 0;
  p2->frag_offset = htons(0x2000 | 100);//MF; Offset=800
  p2->ttl = 42;
  p2->proto = IP_PROTO_ICMP;
  p2->chksum = 0;
  p2->src_addr[0] = 192;
  p2->src_addr[1] = 168;
  p2->src_addr[2] = 0;
  p2->src_addr[3] = 1;
  p2->dst_addr[0] = 192;
  p2->dst_addr[1] = 168;
  p2->dst_addr[2] = 0;
  p2->dst_addr[3] = 2;
  for (i = 0; i < 400; ++i)
    p2->opt[i] = p1->opt[i + 800];
  p2->chksum = ip_compute_checksum(p2, sizeof(struct ip_hdr));

  p3->hlen = 5;
  p3->version = 4;
  p3->tos = 0;
  p3->len = htons(24);
  p3->id = 0;
  p3->frag_offset = htons(150);//MF; Offset=800
  p3->ttl = 42;
  p3->proto = IP_PROTO_ICMP;
  p3->chksum = 0;
  p3->src_addr[0] = 192;
  p3->src_addr[1] = 168;
  p3->src_addr[2] = 0;
  p3->src_addr[3] = 1;
  p3->dst_addr[0] = 192;
  p3->dst_addr[1] = 168;
  p3->dst_addr[2] = 0;
  p3->dst_addr[3] = 2;
  for (i = 0; i < 4; ++i)
    p3->opt[i] = p1->opt[i + 1200];
  p3->chksum = ip_compute_checksum(p3, sizeof(struct ip_hdr));

  unsigned char dest_arp[6];
  unsigned char to[4] = {192,168,0,2};
  arp_resolve(to, dest_arp);
  //  ether_send_frame(dest_arp, ETHER_TYPE_IPV4, p3, 24);
  // ether_send_frame(dest_arp, ETHER_TYPE_IPV4, p2, 420);
  // ether_send_frame(dest_arp, ETHER_TYPE_IPV4, p1, 820);
  ip_handle(NULL, p1, 820);
  //  ip_handle(NULL, p2, 420);
  ip_handle(NULL, p3, 24);

}
