#include <stdio.h>
#include <string.h>
#include "icmp.h"
#include "ip.h"

unsigned short icmp_compute_checksum(void *data, unsigned short len)
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

void icmp_send_reply(unsigned char *to, unsigned char *payload,
		     unsigned short len, unsigned short id, unsigned short sequence)
{
  unsigned char raw[sizeof(struct icmp_hdr) + len];
  struct icmp_hdr *data = (struct icmp_hdr *)&raw;

  data->type = ICMP_TYPE_REPLY;
  data->code = 0;
  data->id = id;
  data->sequence = sequence;
  memcpy(data->padding, payload, len);
  data->checksum = 0;
  data->checksum = icmp_compute_checksum(data, sizeof(raw));
  ip_send_packet(to, IP_PROTO_ICMP, 0, raw, sizeof(raw), 1);
}

void icmp_handle(unsigned char *src_ip, unsigned char *data, unsigned short len)
{
  struct icmp_hdr *pkt = (struct icmp_hdr *)data;
  unsigned short received_checksum;
  
  received_checksum = pkt->checksum;
  pkt->checksum = 0;
  if (icmp_compute_checksum(data, len) != received_checksum)
    {
#ifdef DEBUG_ICMP
      printf("Invalid ICMP Checksum\n");
#endif /* DEBUG_ICMP */
      return;
    }
#ifdef DEBUG_ICMP
  printf("Type %d len %d\n", pkt->type, len);
#endif /* DEBUG_ICMP */
  switch (pkt->type)
    {
    case ICMP_TYPE_REPLY:
#ifdef DEBUG_ICMP
      printf("Echo reply\n");
      int i;
      for (i = 0; i < len; ++i)
	{
	  printf("%02X ", ((unsigned char *)pkt)[i]);
	}
      printf("\n");
#endif /* DEBUG_ICMP */
      break;
    case ICMP_TYPE_REQUEST:
#ifdef DEBUG_ICMP
      printf("Echo request\n");
#endif /* DEBUG_ICMP */
      icmp_send_reply(src_ip, pkt->padding, len - sizeof(struct icmp_hdr), pkt->id, pkt->sequence);
      break;
    default:
      break;      
    }
}
