#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "tcp.h"
#include "ip.h"

struct tcp_sock_tcb tcp_socks[TCP_MAX_SOCKETS];

char *tcp_string_state(enum tcp_sock_state state)
{
  switch (state)
    {
    case LISTEN:
      return "LISTEN";
    case SYN_SENT:
      return "SYN_SENT";
    case SYN_RECEIVED:
      return "SYN_RECEIVED";
    case ESTABLISHED:
      return "ESTABLISHED";
    case FIN_WAIT_1:
      return "FIN_WAIT_1";
    case FIN_WAIT_2:
      return "FIN_WAIT_2";
    case CLOSE_WAIT:
      return "CLOSE_WAIT";
    case CLOSING:
      return "CLOSING";
    case LAST_ACK:
      return "LAST_ACK";
    case TIME_WAIT:
      return "TIME_WAIT";
    case CLOSED:
      return "CLOSED";
    default:
      return "Unknown";
    }
}

enum tcp_sock_state tcp_find_tcb(int *sd,
				 unsigned short local_port,
				 unsigned char remote_ip[],
				 unsigned short remote_port)
{
  int i;

  for (i = 0; i < TCP_MAX_SOCKETS; ++i)
    if (tcp_socks[i].state != CLOSED &&
	tcp_socks[i].local_port == local_port &&
	tcp_socks[i].remote_port == remote_port &&
	memcmp(tcp_socks[i].remote_ip, remote_ip, 4) == 0)
      {
	*sd = i;
	return tcp_socks[i].state;
      }
  return CLOSED;
}

int tcp_open(int passive, unsigned short local_port,
	     unsigned char remote_ip[], unsigned short remote_port)
{
  int sd;
  int i;

  switch (tcp_find_tcb(&sd, local_port, remote_ip, remote_port))
    {
    case CLOSED:
      //Create TCB
      for (i = 0; i < TCP_MAX_SOCKETS; ++i)
	if (tcp_socks[i].state == CLOSED)
	  break;
      if (i == TCP_MAX_SOCKETS)
	{
	  printf("No resource available, unable to create socket\n");
	  return -1;
	}

      //Fill in local and remote sockets ids
      tcp_socks[i].local_port = local_port;
      memcpy(tcp_socks[i].remote_ip, remote_ip, 4);
      tcp_socks[i].remote_port = remote_port;
      tcp_socks[i].passive = passive;

      if (passive)
	{
	  //Enter LISTEN state and return
	  tcp_socks[i].state = LISTEN;
	  return i;
	}
      else
	{
	  //Check that the remote socket has been correctly specified
	  if (memcmp(remote_ip, ip_addr_any, 4) == 0 && remote_port == 0)
	    {
	      printf("Active open requires a valid remote socket parameters\n");
	      return -1;
	    }
	  //Choose an ISS and fill data in TCB
	  tcp_socks[sd].snd_una = htonl(1); //FIXME ISN should be random
	  tcp_socks[sd].snd_nxt = htonl(ntohl(tcp_socks[sd].snd_una) + 1);

	  //TODO send SYN	  
	  printf("TODO: CREATING ACTIVE SOCKET NOT IMPLEMENTED YET\n");

	  //Enter SYN_SENT state
	  tcp_socks[sd].state = SYN_SENT;
	  return i;
	}
      break;
    case LISTEN:
      if (!passive)
	{
	  //The connection is now active
	  tcp_socks[sd].passive = 0;
	  //Check that the remote socket has been correctly specified
	  if (memcmp(remote_ip, ip_addr_any, 4) == 0 && remote_port == 0)
	    {
	      printf("Active open requires a valid remote socket parameters\n");
	      return -1;
	    }
	  //Choose an ISN and fill data in TCB
	  tcp_socks[sd].snd_una = htonl(1); //FIXME ISN should be random
	  tcp_socks[sd].snd_nxt = htonl(ntohl(tcp_socks[sd].snd_una) + 1);

	  //TODO send SYN
	  printf("TODO: CREATING ACTIVE SOCKET (FROM PASSIVE) NOT IMPLEMENTED YET\n");

	  //Enter SYN_SENT state
	  tcp_socks[sd].state = SYN_SENT;
	}
      return sd;
      break;
    default:
      //This socket already exists
      printf("Unable to bind socket, port already in use\n");
      return -1;
    }
  //We should never reach this
  printf("ERROR: This shouldn't have happenned\n");
  return -42;  
}

void tcp_close(int sd)
{
  if (sd < 0 || sd > TCP_MAX_SOCKETS)
    {
      printf("Close failed, invalid socket descriptor\n");
      return;
    }

  switch (tcp_socks[sd].state)
    {
    case CLOSED:
      //We can't close a closed connection
      printf("Close failed: this socket doesn't exist\n");
      return;
      break;
    case LISTEN:
      //Just set the socket as closed
      tcp_socks[sd].state = CLOSED;
      return;      
      break;
    case SYN_SENT:
      //Just set the socket as closed
      tcp_socks[sd].state = CLOSED;
      return;      
      break;
    case SYN_RECEIVED:
      if (1) //FIXME If no data to send
	{
	  //FIXME send FIN
	  tcp_socks[sd].state = FIN_WAIT_1;
	  return;
	}
      else
	{
	  //FIXME wait for ESTABLISHED state and data sent before realy closing
	  return;
	}
      break;
    case ESTABLISHED:
      //FIXME wait for all pending data to be sent
      //FIXME send FIN
      tcp_socks[sd].state = FIN_WAIT_1;
      return;
      break;
    case FIN_WAIT_1:
    case FIN_WAIT_2:
      printf("Error: closing in process\n");
      return;
      break;
    case CLOSE_WAIT:
      //FIXME wait for all pending data to be sent
      //FIXME send FIN
      tcp_socks[sd].state = CLOSING;
      return;
      break;
    default:
      printf("Error, closing in process\n");
      return;
    }
}

void tcp_abort(int sd)
{

}

void tcp_send(int sd, const char *buf, size_t sz, int psh, int urg)
{

}

size_t tcp_recv(int sd, char *buf, size_t sz)
{
  return 0; //TODO
}

struct tcp_sock_tcb *tcp_status(int sd)
{
  if (sd >= 0 && sd < TCP_MAX_SOCKETS)
    return &tcp_socks[sd];
  else
    return NULL;
}

void tcp_init(void)
{
  int i;

  for (i = 0; i < TCP_MAX_SOCKETS; ++i)
    tcp_socks[i].state = CLOSED;
}

unsigned short tcp_compute_checksum(void *data, unsigned short len)
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

void tcp_handle(unsigned char *src_ip, unsigned char *dest_ip, unsigned char *data, unsigned short len)
{
  struct tcp_hdr *pkt = (struct tcp_hdr *)data;
  unsigned int chksmlen = len;
  struct tcp_phdr *chksumbuf = NULL;
  unsigned short orig_checksum;
  unsigned short comp_checksum;
  int i;
  int should_clean = 0;

#ifdef DEBUG_TCP
  printf("TCP packet src_port:%u dst_port:%u seq:%u ack:%u reserved:%u data_offset:%u flags:%x window:%u checksum:0x%04x urg_ptr: 0x%04x size: %u\n",
	 ntohs(pkt->src_port), ntohs(pkt->dst_port),
	 ntohl(pkt->seq_nbr), ntohl(pkt->ack_nbr),
	 pkt->reserved, pkt->data_offset, pkt->flags,
	 ntohs(pkt->window), pkt->checksum,
	 ntohs(pkt->urg_ptr), len - pkt->data_offset * 4);
#endif /* DEBUG_TCP */

  orig_checksum = pkt->checksum;
  pkt->checksum = 0;

  if ((len / 2) * 2 != len)
    chksmlen += 1;
  chksmlen += sizeof(struct tcp_phdr);

  chksumbuf = malloc(chksmlen);
  memcpy(&(chksumbuf->src_addr), src_ip, 4);
  memcpy(&(chksumbuf->dst_addr), dest_ip, 4);
  chksumbuf->zero = 0;
  chksumbuf->proto = IP_PROTO_TCP;
  chksumbuf->tcp_len = htons(len);
  memcpy(chksumbuf->tcp_data, data, len);
  if ((len / 2) * 2 != len)
    chksumbuf->tcp_data[len] = 0;
  comp_checksum = tcp_compute_checksum(chksumbuf, chksmlen);
  free(chksumbuf);
  if (orig_checksum != comp_checksum)
    {
#ifdef DEBUG_TCP
      printf("Invalid TCP Checksum\n");
#endif /* DEBUG_TCP */
      return;
    }

  for (i = 0; i < TCP_MAX_SOCKETS; ++i)
    {
      if (tcp_socks[i].state != CLOSED)
	if ((ntohs(pkt->dst_port) == tcp_socks[i].local_port &&
	     tcp_socks[i].remote_port == 0 &&
	     memcmp(tcp_socks[i].remote_ip, ip_addr_any, 4) == 0)
	    ||
	    (ntohs(pkt->dst_port) == tcp_socks[i].local_port &&
	     tcp_socks[i].remote_port == ntohs(pkt->src_port) &&
	     memcmp(tcp_socks[i].remote_ip, src_ip, 4) == 0)
	    )
	  break;
    }
  
  struct tcp_hdr opkt;
  if (i == TCP_MAX_SOCKETS)
    {
#ifdef DEBUG_TCP
      printf("Incoming TCP packet but no associated socket in TCB\n");
#endif /* DEBUG_TCP */
      
      if (pkt->flags & TCP_FLAG_RST)
	{
#ifdef DEBUG_TCP
	  printf("It was a RST, just ignoring\n");
#endif /* DEBUG_TCP */
	  return;
	}
      
      if (pkt->flags & TCP_FLAG_ACK)
	{
#ifdef DEBUG_TCP
	  printf("It was an ACK, sending RST back\n");
#endif /* DEBUG_TCP */
	  opkt.ack_nbr = 0;
	  opkt.seq_nbr = pkt->ack_nbr;
	  opkt.flags = TCP_FLAG_RST;
	}
      else
	{
#ifdef DEBUG_TCP
	  printf("It was not an ACK or a RST, sending RST/ACK back\n");
#endif /* DEBUG_TCP */
	  opkt.ack_nbr = htonl(ntohl(pkt->seq_nbr) + len - pkt->data_offset * 4 + 1);
	  opkt.seq_nbr = 0;
	  opkt.flags = TCP_FLAG_ACK | TCP_FLAG_RST;
	}
            
      opkt.src_port = pkt->dst_port;
      opkt.dst_port = pkt->src_port;
      opkt.reserved = 0;
      opkt.data_offset = 5;
      opkt.window = htons(0);
      opkt.checksum = 0;
      opkt.urg_ptr = 0;
      
      chksmlen = 12 + sizeof(struct tcp_hdr);
      chksumbuf = malloc(chksmlen);
      memcpy(&(chksumbuf->src_addr), dest_ip, 4);
      memcpy(&(chksumbuf->dst_addr), src_ip, 4);
      chksumbuf->zero = 0;
      chksumbuf->proto = IP_PROTO_TCP;
      chksumbuf->tcp_len = htons(sizeof(struct tcp_hdr));
      memcpy(chksumbuf->tcp_data, &opkt, sizeof(struct tcp_hdr));
      opkt.checksum = tcp_compute_checksum(chksumbuf, chksmlen);
      free(chksumbuf);
      ip_send_packet(src_ip, IP_PROTO_TCP, 0, (unsigned char *)&opkt, sizeof(struct tcp_hdr), 1);            
      return;
    }
  
#ifdef DEBUG_TCP
  printf("Incoming TCP packet, found associated socket in TCB #%d\n", i);
#endif /* DEBUG_TCP */


  switch (tcp_socks[i].state)
    {
    case LISTEN:
      if (pkt->flags & TCP_FLAG_RST)
	return;
      if (pkt->flags & TCP_FLAG_ACK)
	{
	  //TODO Send RST
	  return;
	}
      if (pkt->flags & TCP_FLAG_SYN)
	{
	  tcp_socks[i].rcv_nxt = ntohl(pkt->seq_nbr) + 1;
	  tcp_socks[i].irs = ntohl(pkt->seq_nbr);

	  opkt.src_port = pkt->dst_port;
	  opkt.dst_port = pkt->src_port;
	  opkt.seq_nbr = htonl(1); //FIXME ISN should be random
	  opkt.ack_nbr = htonl(ntohl(pkt->seq_nbr) + 1);
	  opkt.reserved = 0;
	  opkt.data_offset = 5;
	  opkt.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
	  opkt.window = htons(536);
	  opkt.checksum = 0;
	  opkt.urg_ptr = 0;

	  chksmlen = 12 + sizeof(struct tcp_hdr);
	  chksumbuf = malloc(chksmlen);
	  memcpy(&(chksumbuf->src_addr), dest_ip, 4);
	  memcpy(&(chksumbuf->dst_addr), src_ip, 4);
	  chksumbuf->zero = 0;
	  chksumbuf->proto = IP_PROTO_TCP;
	  chksumbuf->tcp_len = htons(sizeof(struct tcp_hdr));
	  memcpy(chksumbuf->tcp_data, &opkt, sizeof(struct tcp_hdr));
	  opkt.checksum = tcp_compute_checksum(chksumbuf, chksmlen);
	  free(chksumbuf);
	  ip_send_packet(src_ip, IP_PROTO_TCP, 0, (unsigned char *)&opkt, sizeof(struct tcp_hdr), 1);

	  tcp_socks[i].snd_nxt = ntohl(opkt.seq_nbr) + 1;
	  tcp_socks[i].snd_una = ntohl(opkt.seq_nbr);

	  tcp_socks[i].state = SYN_RECEIVED;
	  printf("Socket from LISTEN to SYN_RECEIVED\n");
	  return;
	}
      printf("Received a non-syn packet... ignoring\n");
      break;
    case SYN_SENT:
      //TODO
      break;
    case SYN_RECEIVED:
    case ESTABLISHED:
    case FIN_WAIT_1:
    case FIN_WAIT_2:
    case CLOSE_WAIT:
    case CLOSING:
    case LAST_ACK:
    case TIME_WAIT:
      //TODO Test sequence number
      switch (tcp_socks[i].state)
	{
	case SYN_RECEIVED:
	  if (pkt->flags & TCP_FLAG_RST && tcp_socks[i].passive)
	    {
	      tcp_socks[i].state = LISTEN;
	      should_clean = 1;
	    }
	  if (!tcp_socks[i].passive)
	    {
	      printf("Connection refused\n");
	      tcp_socks[i].state = CLOSED;
	      should_clean = 1;
	    }
	  if (should_clean)
	    {
	      //TODO Cleanup retransmit queue
	      return;
	    }
	  break;
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
	  if (pkt->flags & TCP_FLAG_RST)
	    {
	      //TODO Abort all send/receive in progress
	      //TODO Flush internal data
	      tcp_socks[i].state = CLOSED;
	      return;
	    }
	  break;
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
	  if (pkt->flags & TCP_FLAG_RST)
	    {
	      tcp_socks[i].state = CLOSED;
	      return;
	    }
	default:
	  break;
	}
      //4-Check SYN:
      switch (tcp_socks[i].state)
	{
	case SYN_RECEIVED:
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
	  //TODO WTF about SYN in window ?
	  break;
	default:
	  break;
	}
      if (!(pkt->flags & TCP_FLAG_ACK))
	{
	  return;
	}
      else
	{
	  switch (tcp_socks[i].state)
	    {
	    case SYN_RECEIVED:
	      printf("ACK received in SYN_RECEIVED state\n");
	      if (tcp_socks[i].snd_una <= ntohl(pkt->ack_nbr) &&
		  ntohl(pkt->ack_nbr) <= tcp_socks[i].snd_nxt)
		{
		  tcp_socks[i].state = ESTABLISHED;
		  break;
		}
	      else
		{
		  // TODO Send RST
		}
	      break;
	    case ESTABLISHED:
	    case FIN_WAIT_1:
	    case FIN_WAIT_2:
	    case CLOSE_WAIT:
	    case CLOSING:
	      //TODO
	      if (tcp_socks[i].state == FIN_WAIT_1)
		{
		  //TODO
		}
	      else if (tcp_socks[i].state == FIN_WAIT_2)
		{
		  //TODO
		}
	      else if (tcp_socks[i].state == CLOSING)
		{

		}
	      break;
	    case LAST_ACK:
	      //TODO
	      break;
	    case TIME_WAIT:
	      //TODO
	      break;
	    default:
	      break;
	    }
	}
      //6-Check URG
      switch (tcp_socks[i].state)
	{
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	  //TODO
	  break;
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
	  //TODO
	  break;
	default:
	  break;
	}
      //7-Get data
      switch (tcp_socks[i].state)
	{
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	  //TODO
	  break;
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
	  //TODO
	  break;
	default:
	  break;
	}
      //8-Check FIN
      switch (tcp_socks[i].state)
	{
	case CLOSED:
	case LISTEN:
	case SYN_SENT:
	  return;
	  break;
	default:
	  if (pkt->flags & TCP_FLAG_FIN)
	    {
	      //TODO
	    }
	  break;
	}
      break;
    default:
      break;
    }

#ifdef DEBUG_TCP
  printf("This is a SYN, sending SYN/ACK back\n");
#endif /* DEBUG_TCP */
}

void tcp_dump_tcb(void)
{
  int i;

  printf("--- TCP TCB ---\n");
  for (i = 0; i < TCP_MAX_SOCKETS; ++i)
    {
      if (tcp_socks[i].state != CLOSED)
	{
	  printf("%02d\t000.000.000.000:%05d\t%03d.%03d.%03d.%03d:%05d\t%s\n",
		 i,
		 tcp_socks[i].local_port,
		 tcp_socks[i].remote_ip[0],
		 tcp_socks[i].remote_ip[1],
		 tcp_socks[i].remote_ip[2],
		 tcp_socks[i].remote_ip[3],
		 tcp_socks[i].remote_port,
		 tcp_string_state(tcp_socks[i].state)); 
	}
    }  
  printf("---------------\n");
}
