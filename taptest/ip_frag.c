#include "ip_frag.h"

#include <stdlib.h>

struct ip_frag_table_entry *ip_frag_table = NULL;

void ip_frag_init(void)
{
    ip_frag_table = NULL;
}

void ip_frag_dump(void)
{
  struct ip_frag_table_entry *iterator = ip_frag_table;

  printf("--- IP Fragments table ---\n");
  while (iterator != NULL)
    {
      printf(" FRAG_RES - %d.%d.%d.%d-%d.%d.%d.%d-%d-%d - %ld\n",
	     iterator->bufid.src_addr[0],
	     iterator->bufid.src_addr[1],
	     iterator->bufid.src_addr[2],
	     iterator->bufid.src_addr[3],
	     iterator->bufid.dst_addr[0],
	     iterator->bufid.dst_addr[1],
	     iterator->bufid.dst_addr[2],
	     iterator->bufid.dst_addr[3],
	     iterator->bufid.proto,
	     iterator->bufid.id,
	     iterator->expires - time(NULL));
      iterator = iterator->next;
    }
  printf("--------------------------\n");
}

void ip_frag_free_element(struct ip_frag_table_entry *element)
{
  free(element);
}

struct ip_frag_table_entry *ip_frag_find_bufid(struct ip_frag_bufid *bufid)
{
  struct ip_frag_table_entry *iterator = ip_frag_table;

  while (iterator != NULL)
    {
      if (memcmp(&(iterator->bufid), bufid, sizeof(struct ip_frag_bufid)) == 0)
	return iterator;
      iterator = iterator->next;
    }

  // No match
  return NULL;
}

void ip_frag_flush_expired(void)
{
  struct ip_frag_table_entry *iterator;
  struct ip_frag_table_entry *prev;

  // Empty list, return immediately
  if (ip_frag_table == NULL)
    return;

  // If we match the first element, update ip_frag_table pointer itself
  while (ip_frag_table && ip_frag_table->expires - time(NULL) <= 0)
    {
      iterator = ip_frag_table;
      ip_frag_table = ip_frag_table->next;
      ip_frag_free_element(iterator);
    }

  // Empty list, return immediately
  if (ip_frag_table == NULL)
    return;

  // Go through the list and remove elements
  prev = ip_frag_table;
  iterator = ip_frag_table->next;
  while (iterator != NULL)
    {
      if (iterator->expires - time(NULL) <= 0)
	{
	  struct ip_frag_table_entry *todel = iterator;
	  prev->next = iterator->next;
	  iterator = iterator->next;
	  ip_frag_free_element(todel);
	}
      else
	{
	  prev = iterator;
	  iterator = iterator->next;
	}
    }
}

void ip_frag_flush_bufid(struct ip_frag_bufid *bufid)
{
  struct ip_frag_table_entry *iterator;
  struct ip_frag_table_entry *prev;

  // Empty list, return immediately
  if (ip_frag_table == NULL)
    return;

  // If we match the first element, update ip_frag_table pointer itself
  if (memcmp(&(ip_frag_table->bufid), bufid, sizeof(struct ip_frag_bufid)) == 0)
    {
      iterator = ip_frag_table;
      ip_frag_table = ip_frag_table->next;
      ip_frag_free_element(iterator);
    }
  else
    {
      // Otherwise, go through the list and remove element if found
      prev = ip_frag_table;
      iterator = ip_frag_table->next;
      while (iterator != NULL)
	{
	  if (memcmp(&(iterator->bufid), bufid, sizeof(struct ip_frag_bufid)) == 0)
	    {
	      prev->next = iterator->next;
	      ip_frag_free_element(iterator);
	      break;
	    }
	  prev = iterator;
	  iterator = iterator->next;
	}
    }
}

struct ip_frag_table_entry *ip_frag_new_element(struct ip_frag_bufid *bufid)
{
  struct ip_frag_table_entry *res = NULL;

  res = malloc(sizeof(struct ip_frag_table_entry));
  if (res != NULL)
    {
      memcpy(&(res->bufid), bufid, sizeof(struct ip_frag_bufid));
      res->dlen = 0;
      res->expires = time(NULL) + IP_FRAG_EXPIRE_TIMER;
      bzero(res->rcvbt, 65536 / 8);
#ifdef DEBUG_IP
      bzero(res->dbuf, 65536);
#endif /* DEBUG_IP */
      res->next = ip_frag_table;
      ip_frag_table = res;
    }
  return res;
}

void ip_frag_handle(struct ip_hdr *pkt, struct ip_frag_bufid *bufid)
{
      struct ip_frag_table_entry *entry;
      entry = ip_frag_find_bufid(bufid);
      if (entry == NULL)
	{
#ifdef DEBUG_IP
	  printf("First received fragment of an IP packet, allocating resource\n");
#endif /* DEBUG_IP */
	  entry = ip_frag_new_element(bufid);
	}
      memcpy((unsigned char *) &(entry->dbuf) + ((ntohs(pkt->frag_offset) & 0x1fff) * 8),
	     ((unsigned char *)pkt + pkt->hlen * 4),
	     ntohs(pkt->len) - pkt->hlen * 4);
      int i;
      for (i = ntohs(pkt->frag_offset) & 0x1fff; i < (ntohs(pkt->frag_offset) & 0x1fff) + ((ntohs(pkt->len) - (pkt->hlen * 4) + 7) / 8); ++i)
	{
	  entry->rcvbt[i] = 1;
	}
      if ((ntohs(pkt->frag_offset) & 0x2000) == 0)
	{
	  entry->dlen = ntohs(pkt->len) - (pkt->hlen * 4) + ((ntohs(pkt->frag_offset) & 0x1fff) * 8);
#ifdef DEBUG_IP
	  printf("Last fragment of an IP packet received, the size of the packet is now known: %d\n", entry->dlen);
#endif /* DEBUG_IP */
	}
      if ((ntohs(pkt->frag_offset) & 0x1fff) == 0)
	{
#ifdef DEBUG_IP
	  printf("First fragment of an IP packet received, extracting header\n");
#endif /* DEBUG_IP */
	  memcpy(&(entry->hbuf), pkt, pkt->hlen * 4);
	}
      if (entry->dlen != 0)
	{
	  // Do we have all fragments ?
	  char missing = 0;
	  for (i = 0; i < (entry->dlen + 7) / 8; ++i)
	    {
	      if (entry->rcvbt[i] == 0)
		{
		  missing = 1;
		  break;
		}
	    }
	  if (missing == 0)
	    {
#ifdef DEBUG_IP
	      printf("All fragments received\n");
#endif /* DEBUG_IP */
	      // Reassembling packet
	      unsigned char buf[65536];
	      struct ip_hdr *rpkt = &buf;
	      unsigned char hlen = ((struct ip_hdr *)entry->hbuf)->hlen;
	      memcpy(rpkt, &(entry->hbuf), hlen * 4);
	      memcpy((unsigned char *)rpkt + (hlen * 4), &(entry->dbuf), entry->dlen);
	      rpkt->len = htons(entry->dlen + hlen * 4);
	      ip_deliver_packet(rpkt);
	      ip_frag_flush_bufid(bufid);
	    }
	}
}
