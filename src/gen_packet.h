#ifndef GEN_PACKET_H
#define GEN_PACKET_H

void init_send_buff(void *buff, int type, size_t len);
void * make_rst_packet(void *buff, size_t *len, \
		const u_char *pkt, int type, \
		int reverse, int do_csum);

void reverse_packet(void *buff, tcp_seq th_ack);

int inject_raw_packet(int socket, void *buff);

#endif
