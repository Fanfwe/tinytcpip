#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "ether.h"
#include "ip.h"
#include "arp.h"
#include "tcp.h"

char dev[]="tap0";

int tap_fd;

int tap_alloc(char *dev)
{
  struct ifreq ifr;
  int fd, err;
  
  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    return -1;
  
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI; 
  if (*dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  
  if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
      close(fd);
      return err;
    }
  strcpy(dev, ifr.ifr_name);

  return fd;
}   

int main()
{
  char buf[1522];
  int fd;
  int sock_fd;
  time_t t;

  fd = tap_alloc(dev);
#ifdef DEBUG_TAP
  printf("device %s\n", dev);
#endif /* DEBUG_TAP */
  tap_fd = fd;

  sprintf(buf, "ifconfig %s 192.168.0.1 netmask 255.255.255.0 up", dev);
  system(buf);

  arp_init();
  ip_init();
  tcp_init();

  sock_fd = tcp_open(1, 4242, ip_addr_any, 0);

  printf("Server socket fd is %d\n", sock_fd);

    send_fragments();
  /* return 0; */

  t = time(NULL);
  while(1)
    {
      if (ether_can_recv())
	ether_recv_frame();
      if (time(NULL) != t)
	{
	  t = time(NULL);

	  ip_frag_flush_expired();

	  tcp_dump_tcb();
	  ip_frag_dump();

	}
    }

  return 0;
}
