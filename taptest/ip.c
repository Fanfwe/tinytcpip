#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "ether.h"
#include "tcp.h"

unsigned char ip_address[4];
unsigned char ip_addr_any[4] = {0,0,0,0};
unsigned short ip_id;

void ip_init(void)
{
  ip_address[0] = 192;
  ip_address[1] = 168;
  ip_address[2] = 0;
  ip_address[3] = 2;
  ip_id = 0;
  ip_frag_init();
}

unsigned short ip_compute_checksum(void *data, unsigned short len)
{
  unsigned short *buf = data;
  unsigned long res = 0;
  int i;

  res = buf[0];
  for (i = 1; i < len / 2; ++i)
    res += buf[i];
  res = (res >> 16) + (res & 0xffff);
  res = res + (res >> 16);
  return (unsigned short)~res;
}

void ip_send_packet(unsigned char *to, unsigned char proto, unsigned char tos,
		    unsigned char *payload, unsigned short len, unsigned int nofrag)
{
  unsigned char raw[sizeof(struct ip_hdr) + len];
  struct ip_hdr *data = (struct ip_hdr *)&raw;
  unsigned char dest_arp[6];
  
  
#ifdef DEBUG_IP
      printf("Sending IP packet\n");
#endif /* DEBUG_IP */

  data->hlen = 5;
  data->version = 4;
  data->tos = tos;
  data->len = htons(sizeof(raw));
  data->id = htons(ip_id++);
  data->frag_offset = htons(!!nofrag ? 0x4000 : 0);
  data->ttl = 42;
  data->proto = proto;
  data->chksum = 0;
  memcpy(data->src_addr, ip_address, 4);
  memcpy(data->dst_addr, to, 4);
  memcpy(data->opt, payload, len);
  data->chksum = ip_compute_checksum(raw, sizeof(struct ip_hdr));
  arp_resolve(to, dest_arp);
  ether_send_frame(dest_arp, ETHER_TYPE_IPV4, raw, sizeof(raw));
}

void ip_handle(unsigned char *src_mac, unsigned char *data, unsigned short len)
{
  struct ip_hdr *pkt = (struct ip_hdr *)data;
  unsigned short orig_checksum;
  
  orig_checksum = pkt->chksum;
  pkt->chksum = 0;
  if (orig_checksum != ip_compute_checksum(data, pkt->hlen * 4))
    {
#ifdef DEBUG_IP
      printf("Invalid IP Checksum\n");
#endif /* DEBUG_IP */
      return;
    }

#ifdef DEBUG_IP
  printf("IP packet from %d.%d.%d.%d type %d hlen %d frag %d MF %d\n",
	 pkt->src_addr[0], pkt->src_addr[1],
	 pkt->src_addr[2], pkt->src_addr[3],
	 pkt->proto, pkt->hlen * 4, ntohs(pkt->frag_offset) & 0x1fff, !!(ntohs(pkt->frag_offset) & 0x2000));
#endif /* DEBUG_IP */

  // Compute bufid
  struct ip_frag_bufid bufid;
  memcpy(&(bufid.src_addr), &(pkt->src_addr), 4);
  memcpy(&(bufid.dst_addr), &(pkt->dst_addr), 4);
  bufid.proto = pkt->proto;
  bufid.id = ntohs(pkt->id);
  
  if ((ntohs(pkt->frag_offset) & 0x3fff) == 0) //Fragment offset = 0 and More fragments = 0
    {
      //This packet has not been fragmented
      ip_frag_flush_bufid(&bufid);
      ip_deliver_packet(pkt);
    }
  else
    {
      //This is a fragment
      ip_frag_handle(pkt, &bufid);
    }
}

void ip_deliver_packet(struct ip_hdr *pkt)
{
  switch (pkt->proto)
    {
    case IP_PROTO_ICMP:
#ifdef DEBUG_IP
      printf("ICMP\n");
#endif /* DEBUG_IP */
      icmp_handle(pkt->src_addr, ((unsigned char *)pkt + pkt->hlen * 4),
		  ntohs(pkt->len) - pkt->hlen * 4);
      break;
    case IP_PROTO_TCP:
#ifdef DEBUG_IP
      printf("TCP\n");
#endif /* DEBUG_IP */
      tcp_handle(pkt->src_addr, pkt->dst_addr,
		 ((unsigned char *)pkt + pkt->hlen * 4),
		  ntohs(pkt->len) - pkt->hlen * 4);
      break;
    case IP_PROTO_UDP:
#ifdef DEBUG_IP
      printf("UDP\n");
#endif /* DEBUG_IP */
      break;
    default:
      break;
    }
}
