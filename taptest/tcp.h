#ifndef TCP_H_
# define TCP_H_

#define TCP_MAX_SOCKETS 16

#define TCP_FLAG_FIN	1
#define TCP_FLAG_SYN	2
#define TCP_FLAG_RST	4
#define TCP_FLAG_PSH	8
#define TCP_FLAG_ACK	16
#define TCP_FLAG_URG	32

enum tcp_sock_state
  {
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    CLOSED
  };

struct tcp_sock_tcb
{
  unsigned short local_port;
  unsigned char remote_ip[4];
  unsigned short remote_port;
  unsigned long snd_una;
  unsigned long snd_nxt;
  unsigned short snd_wnd;
  unsigned short snd_up;
  unsigned short snd_wl1;
  unsigned short snd_wl2;
  unsigned long iss;
  unsigned long rcv_nxt;
  unsigned short rcv_wnd;
  unsigned short rcv_up;
  unsigned long irs;
  unsigned long seg_seq;
  unsigned long seg_ack;
  unsigned short seg_len;
  unsigned short seg_wnd;
  unsigned short seg_up;
  unsigned short seg_prc;
  enum tcp_sock_state state;
  int passive;
};

struct tcp_hdr
{
  unsigned short src_port;
  unsigned short dst_port;
  unsigned long seq_nbr;
  unsigned long ack_nbr;
  unsigned int reserved:4;
  unsigned int data_offset:4;
  unsigned char flags;
  unsigned short window;
  unsigned short checksum;
  unsigned short urg_ptr;
  unsigned char opt[];
} __attribute__((packed));

struct tcp_phdr
{
  unsigned long src_addr;
  unsigned long dst_addr;
  unsigned char zero;
  unsigned char proto;
  unsigned short tcp_len;
  unsigned char tcp_data[];
} __attribute__((packed));

int tcp_open(int passive, unsigned short local_port,
	     unsigned char remote_ip[], unsigned short remote_port);
void tcp_send(int sd, const char *buf, size_t sz, int psh, int urg);
size_t tcp_recv(int sd, char *buf, size_t sz);
void tcp_close(int sd);
struct tcp_sock_tcb *tcp_status(int sd);
void tcp_abort(int sd);


void tcp_init(void);
unsigned short tcp_compute_checksum(void *data, unsigned short len);
void tcp_handle(unsigned char *src_ip, unsigned char *dest_ip, unsigned char *data, unsigned short len);
void tcp_dump_tcb(void);

#endif /* TCP_H_ */
