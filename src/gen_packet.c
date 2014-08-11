#if defined(__linux__)
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#include <sys/socket.h>
#endif
#endif

#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#if defined(__linux__)
#include <pcap/bpf.h>
#include <pcap/sll.h>
#else
#include <net/bpf.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "chksum.h"

void *
align(void *p, size_t offset, size_t align_to)
{
	size_t r = (size_t)(p + offset) % align_to;
	return p + (align_to - r) % align_to;
}

void *
make_rst_packet(void *buff, size_t *len, \
		const u_char *pkt, int type, \
		int reverse, int do_csum)
{
	struct ip *ih;
	struct ip *pkt_ih;

	switch (type) {
	case DLT_NULL:
		{
			buff = align(buff, 4, sizeof(int32_t));
			ih = buff + 4;
			pkt_ih = (void *)pkt + 4;
		}
		break;
	case DLT_EN10MB:
		{
			buff = align(buff, ETHER_HDR_LEN, sizeof(int32_t));
			struct ether_header *eh = buff;
			struct ether_header *pkt_eh = (struct ether_header *)pkt;
			if (reverse) {
				memcpy(&eh->ether_dhost, &pkt_eh->ether_dhost, ETHER_ADDR_LEN);
				memcpy(&eh->ether_shost, &pkt_eh->ether_shost, ETHER_ADDR_LEN);
			} else {
				memcpy(&eh->ether_dhost, &pkt_eh->ether_shost, ETHER_ADDR_LEN);
				memcpy(&eh->ether_shost, &pkt_eh->ether_dhost, ETHER_ADDR_LEN);
			}
			ih = buff + ETHER_HDR_LEN;
			pkt_ih = (void *)pkt + ETHER_HDR_LEN;
		}
		break;
	case DLT_PPP:
		{
			buff = align(buff, sizeof(struct pppheader), sizeof(int32_t));
			struct pppheader *ph = buff;
			struct pppheader *pkt_ph = (struct pppheader *)pkt;
			memcpy(ph, pkt_ph, sizeof(*ph));
			ih = buff + sizeof(*ph);
			pkt_ih = (void *)pkt + sizeof(*ph);
		}
		break;
#if defined(__linux__)
	case DLT_LINUX_SLL:
		{
			buff = align(buff, SLL_HDR_LEN, sizeof(int32_t));
			struct sll_header *sh = buff;
			struct sll_header *pkt_sh = (struct sll_header *)pkt;
			memcpy(sh, pkt_sh, sizeof(*sh));
			if (!reverse)
				sh->sll_pkttype = htons(LINUX_SLL_OUTGOING);
			ih = buff + SLL_HDR_LEN;
			pkt_ih = (void *)pkt + SLL_HDR_LEN;
		}
		break;
#endif
	default:
		errx(EXIT_FAILURE, "unsupported link layer type %d", type);
	}

	ih->ip_id = rand() ^ pkt_ih->ip_id;
	if (reverse) {
		ih->ip_src = pkt_ih->ip_src;
		ih->ip_dst = pkt_ih->ip_dst;
	} else {
		ih->ip_src = pkt_ih->ip_dst;
		ih->ip_dst = pkt_ih->ip_src;
	}
	ih->ip_sum = 0;
	
	if (do_csum)
		ih->ip_sum = in_cksum((u_int16_t *)ih, 20);

	struct tcphdr *th = (void *)ih + 20;
	struct tcphdr *pkt_th = (void *)pkt_ih + 20;
	if (reverse) {
		th->th_sport = pkt_th->th_sport;
		th->th_dport = pkt_th->th_dport;
		th->th_seq = pkt_th->th_seq;
		th->th_ack = pkt_th->th_ack;
	} else {
		th->th_sport = pkt_th->th_dport;
		th->th_dport = pkt_th->th_sport;
		th->th_seq = pkt_th->th_ack;
		uint32_t ack = ntohs(pkt_ih->ip_len) \
			       - (pkt_ih->ip_hl << 2) \
			       - (pkt_th->th_off << 2) \
			       + ntohl(pkt_th->th_seq);
		th->th_ack = htonl(ack);
	}
	th->th_sum = 0;

	struct tcp_pshdr phdr;
	phdr.ip_src = ih->ip_src;
	phdr.ip_dst = ih->ip_dst;
	phdr.padding = 0;
	phdr.protocol = IPPROTO_TCP;
	phdr.length = htons(20);

	u_int32_t sum = chksum((u_int16_t *)&phdr, 0, sizeof(phdr));
	th->th_sum = final_sum(chksum((u_int16_t *)th, sum, 20));

	*len = 40 + ((void *)ih - buff);
	return buff;
}

int
inject_raw_packet(int socket, void *buff)
{
	struct sockaddr_in dst;
	struct ip *ih = buff;

	dst.sin_family = AF_INET;
	dst.sin_addr = ih->ip_dst;
	
	return sendto(socket, buff, ntohs(ih->ip_len), 0, (struct sockaddr *)&dst, \
			sizeof(dst));
}

void
reverse_packet(void *buff, tcp_seq th_ack)
{
	struct ether_header *eh = buff;
	char tmp[ETHER_ADDR_LEN];
	memcpy(tmp, &eh->ether_shost, ETHER_ADDR_LEN);
	memcpy(&eh->ether_shost, &eh->ether_dhost, ETHER_ADDR_LEN);
	memcpy(&eh->ether_dhost, tmp, ETHER_ADDR_LEN);

	struct ip *ih = buff + ETHER_HDR_LEN;
	struct in_addr ip_tmp;
	ih->ip_id = rand() & 0xffff;
	ip_tmp = ih->ip_src;
	ih->ip_src = ih->ip_dst;
	ih->ip_dst = ip_tmp;
	ih->ip_sum = 0;
	ih->ip_sum = in_cksum((u_int16_t *)ih, 20);

	struct tcphdr *th = (void *)ih + 20;
	unsigned short port_tmp = th->th_sport;
	th->th_sport = th->th_dport;
	th->th_dport = port_tmp;
	th->th_seq = th_ack;
	th->th_sum = 0;

	struct tcp_pshdr phdr;
	phdr.ip_src = ih->ip_src;
	phdr.ip_dst = ih->ip_dst;
	phdr.padding = 0;
	phdr.protocol = IPPROTO_TCP;
	phdr.length = htons(20);
	u_int32_t sum = chksum((u_int16_t *)&phdr, 0, sizeof(phdr));
	th->th_sum = final_sum(chksum((u_int16_t *)th, sum, 20));
}

void
init_send_buff(void *buff, int type, size_t len)
{
	struct ether_header *eh;
	struct ip *ih;
	struct tcphdr *th;

	memset(buff, 0, len);

	switch (type) {
	case DLT_NULL:
		{
			buff = align(buff, 4, sizeof(int32_t));
			ih = buff + 4;
		}
		break;
	case DLT_EN10MB:
		{
			buff = align(buff, ETHER_HDR_LEN, sizeof(int32_t));
			struct ether_header *eh = buff;
			eh->ether_type = htons(ETHERTYPE_IP);
			ih = buff + ETHER_HDR_LEN;
		}
		break;
	case DLT_PPP:
		{
			buff = align(buff, sizeof(struct pppheader), sizeof(int32_t));
			struct pppheader *ph = buff;
			ih = buff + sizeof(*ph);
		}
		break;
#if defined(__linux__)
	case DLT_LINUX_SLL:
		{
			buff = align(buff, SLL_HDR_LEN, sizeof(int32_t));
			struct sll_header *sh = buff;
			ih = buff + SLL_HDR_LEN;
		}
		break;
#endif
	default:
		errx(EXIT_FAILURE, "unsupported link layer type %d", type);
	}

	ih->ip_hl = 5;
	ih->ip_v = 4;
	ih->ip_len = htons(40);
	ih->ip_off = htons(IP_DF);
	ih->ip_ttl = 64;
	ih->ip_p = IPPROTO_TCP;

	th = (void *)ih + 20;
	th->th_off = 5;
	th->th_flags = TH_RST + TH_ACK;
	th->th_win = htons(65535);
}


