#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include "ether.h"
#include "arp.h"
#include "ip.h"

/*- TEMPORARY -*/
extern int tap_fd;
/*-------------*/

unsigned char mac_address[6] = {0x00, 0xff, 0x42, 0x12, 0x34, 0x56};
unsigned char bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void ether_send_frame(unsigned char *to, unsigned short type,
		      unsigned char *payload, unsigned short size)
{
  unsigned char raw[sizeof(struct ether_hdr) + size];
  struct ether_hdr *data = (struct ether_hdr *)&raw;

#ifdef DEBUG_ETHER
  printf("Sending size %d\n", size);
#endif /* DEBUG_ETHER */

  memcpy(data->src_mac, mac_address, 6);
  memcpy(data->dst_mac, to, 6);
  data->type = htons(type);
#ifdef DEBUG_ETHER
  printf("Send 0x%04x 0x%04x\n", type, data->type);
#endif /* DEBUG_ETHER */
  memcpy(data->payload, payload, size);
  write(tap_fd, data, sizeof(struct ether_hdr) + size);
}

void ether_recv_frame(void)
{
  int len;
  char buf[1522];
  struct ether_hdr *ether_data = (struct ether_hdr *)buf;

  len = read(tap_fd, buf, 1522);
  if (len <= 0)
    return;

#ifdef DEBUG_ETHER
  printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x protocol 0x%04x\n",
	 ether_data->src_mac[0], ether_data->src_mac[1],
	 ether_data->src_mac[2], ether_data->src_mac[3],
	 ether_data->src_mac[4], ether_data->src_mac[5],
	 ether_data->dst_mac[0], ether_data->dst_mac[1],
	 ether_data->dst_mac[2], ether_data->dst_mac[3],
	 ether_data->dst_mac[4], ether_data->dst_mac[5],
	     ntohs(ether_data->type));
#endif /* DEBUG_ETHER */
  if (memcmp(ether_data->dst_mac, mac_address, 6) == 0 ||
      memcmp(ether_data->dst_mac, bcast_mac, 6) == 0)
    {
#ifdef DEBUG_ETHER
      printf("This one is for me\n");
#endif /* DEBUG_ETHER */
      switch (ntohs(ether_data->type))
	{
	case ETHER_TYPE_ARP:
	  arp_handle(ether_data->src_mac, ether_data->payload, len);
	  break;
	case ETHER_TYPE_IPV4:
	  ip_handle(ether_data->src_mac, ether_data->payload, len);
	  break;
	default:
	  break;
	}
    }
}

int ether_can_recv()
{
  fd_set fds;
  struct timeval tv;

  FD_ZERO(&fds);
  FD_SET(tap_fd, &fds);
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  return select(tap_fd + 1, &fds, NULL, NULL, &tv);
}
