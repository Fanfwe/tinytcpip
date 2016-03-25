#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "arp.h"
#include "ether.h"
#include "ip.h"

/*- TEMPORARY -*/
extern unsigned char mac_address[];
/*-------------*/

struct arp_table_entry arp_table[256];

void arp_init(void)
{
  int i;

  for (i = 0; i < 256; ++i)
    arp_table[i].present = 0;
}

void arp_table_dump(void)
{
  int i;

#ifdef DEBUG_ARP
  printf("--- ARP TABLE --------------------\n");
  for (i = 0; i < 256; ++i)
    {
      if (arp_table[i].present)
	{
	  printf("%d.%d.%d.%d %02X:%02X:%02X:%02X:%02X:%02X\n",
		 arp_table[i].ip_addr[0],
		 arp_table[i].ip_addr[1],
		 arp_table[i].ip_addr[2],
		 arp_table[i].ip_addr[3],
		 arp_table[i].mac_addr[0],
		 arp_table[i].mac_addr[1],
		 arp_table[i].mac_addr[2],
		 arp_table[i].mac_addr[3],
		 arp_table[i].mac_addr[4],
		 arp_table[i].mac_addr[5]);
	}
    }  
  printf("----------------------------------\n");
#endif /* DEBUG_ARP */
}

void arp_table_add(unsigned char *ip_addr, unsigned char *mac_addr)
{
  int i;
  int last_available = -1;
  int oldest = -1;

  for (i = 0; i < 256; ++i)
    {
      if (arp_table[i].present)
	{
	  if (memcmp(ip_addr, arp_table[i].ip_addr, 4) == 0)
	    {
	      memcpy(arp_table[i].mac_addr, mac_addr, 6);
	      arp_table[i].age = time(NULL);
	      return;
	    }
	  if (oldest == -1)
	    oldest = i;
	  else
	    if (arp_table[i].age < arp_table[oldest].age)
	      oldest = i;
	}
      else
	last_available = i;
    }
  if (last_available != -1)
    {
      memcpy(arp_table[last_available].mac_addr, mac_addr, 6);
      memcpy(arp_table[last_available].ip_addr, ip_addr, 4);
      arp_table[last_available].present = 1;
      arp_table[last_available].age = time(NULL);
    }
  else
    {
      memcpy(arp_table[oldest].mac_addr, mac_addr, 6);
      memcpy(arp_table[oldest].ip_addr, ip_addr, 4);
      arp_table[oldest].age = time(NULL);
    }
  arp_table_dump();
}

void arp_resolve(unsigned char *to, unsigned char *dest_arp)
{
  int i;

  for (i = 0; i < 256; ++i)
    {
      if (arp_table[i].present)
	{
	  if (memcmp(to, arp_table[i].ip_addr, 4) == 0)
	    {
	      memcpy(dest_arp, arp_table[i].mac_addr, 6);
	      break;
	    }
	}
    }
#ifdef DEBUG_ARP
  if (i == 256)
    {
      printf("ARP ENTRY NOT FOUND !\n");
    }
#endif /* DEBUG_ARP */
}

void arp_send_reply(unsigned char *to, unsigned char *sha,
		    unsigned char *spa, unsigned char *tpa)
{
  struct arp_hdr data;

  data.hw_type = htons(1);
  data.proto_type = htons(0x0800);
  data.hw_len = 6;
  data.proto_len = 4;
  data.oper = htons(ARP_OPER_REPLY);
  memcpy(data.sha, mac_address, 6);
  memcpy(data.spa, tpa, 4);
  memcpy(data.tha, sha, 6);
  memcpy(data.tpa, spa, 4);
  ether_send_frame(to, ETHER_TYPE_ARP, (unsigned char *)&data, sizeof(data));
}

void arp_handle(unsigned char *src_mac, unsigned char *data, unsigned short len)
{
  struct arp_hdr *pkt = (struct arp_hdr *)data;

  switch (ntohs(pkt->oper))
    {
    case ARP_OPER_REQUEST:
#ifdef DEBUG_ARP
      printf("ARP Request for %d.%d.%d.%d\n",
	     pkt->tpa[0], pkt->tpa[1],
	     pkt->tpa[2], pkt->tpa[3]);
#endif /* DEBUG_ARP */
      arp_table_add(pkt->spa, pkt->sha);
      if (memcmp(pkt->tpa, ip_address, 4) == 0)
	arp_send_reply(src_mac, pkt->sha, pkt->spa, pkt->tpa);
      break;
    case ARP_OPER_REPLY:
#ifdef DEBUG_ARP
      printf("ARP Reply\n");
#endif /* DEBUG_ARP */
      arp_table_add(pkt->spa, pkt->sha);
      break;
    default:
      break;
    }
}
