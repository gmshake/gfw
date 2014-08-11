#if defined(__linux__)
#define _BSD_SOURCE
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <pcap.h>

#if defined(__linux__)
#include <pcap/sll.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <time.h>
#include <unistd.h>

#include "gen_packet.h"
#include "hexdump.h"
#include "misc.h"
#include "chksum.h"

#define MAX_CAP_LEN 128

pcap_t *handle;		/* Session handle */
int link_type;

#if defined(__linux__)
int raw_socket;
#endif

u_int32_t buff[16]; /* send buff, aligned */

void
act(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	const u_char *p;
	u_int size_ip;
	u_int size_tcp;
	ssize_t len;

	struct tcphdr *tcphdr;
	struct ip *iphdr;

	switch (link_type) {
	case DLT_NULL:
		p = pkt + 4;
		break;
	case DLT_EN10MB:
		p = pkt + ETHER_HDR_LEN; /* skip ETHERNET header */
		break;
	case DLT_PPP:
		p = pkt + sizeof(struct pppheader);
		break;
#if defined(__linux__)
	case DLT_LINUX_SLL:
		p = pkt + SLL_HDR_LEN;
		break;
#endif
	default:
		warnx("unsupported link layer type %d", link_type);
		return;
	}

	iphdr = (struct ip *)p;
	size_ip = iphdr->ip_hl * 4;

	p += size_ip; /* skip IP header */

	tcphdr = (struct tcphdr *)p;
	size_tcp = tcphdr->th_off * 4;

	p += size_tcp; /* skip TCP header */

	len = hdr->caplen - (p - pkt);
	/* check packet */
	if (size_ip < 20 || size_tcp < 20 || len < 0) {
		fprintf(stderr, "invalid packet, IP header len: %u, TCP header len: %u, caplen: %u\n", size_ip, size_tcp, hdr->caplen);
		hexdump(pkt, hdr->caplen);
		return;
	}

	if (strnstr((char *)p, "love", len)) {
		fprintf(stdout, "%d.%d get packet, len %d:\n", \
				hdr->ts.tv_sec, hdr->ts.tv_usec / 1000, \
				hdr->len);

//		printf("---->captured packet:\n");
//		hexdump(pkt, hdr->caplen);

//		printf("---->rst packet to be sent:\n");
//		hexdump(to_be_sent, to_be_sent_len);

		void *psent;
		size_t slen;
		int rval;

		if (link_type == DLT_LINUX_SLL) {
#if defined(__linux__)
			psent = SLL_HDR_LEN + make_rst_packet(buff, &slen, pkt, link_type, 0, 0);
			if ((rval = inject_raw_packet(raw_socket, psent )) < 0)
				warn("send raw socket");
#endif
		} else {
			psent = make_rst_packet(buff, &slen, pkt, link_type, 0, 1);
			if ((rval = pcap_inject(handle, psent, slen)) == -1)
				pcap_perror(handle, "pcap_inject()");
		}

		fprintf(stdout, "send a RST packet to %s, rval = %d\n", \
				inet_ntoa(iphdr->ip_src), rval);
	}
}

int
main(int argc, char *argv[])
{
	char *dev = "any";		/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char *filter_exp = "tcp port 9001";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	if (argc < 2) {
		if (dev == NULL)
			dev = pcap_lookupdev(errbuf);
	} else
		dev = argv[1];

	if (argc == 3)
		filter_exp = argv[2];
	else if (argc > 3)
		errx(EXIT_FAILURE, "invalid parameters");

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("listen on %s\n", dev);

	srand(time(NULL) ^ getpid());
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, MAX_CAP_LEN, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 1, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setdirection(handle, PCAP_D_IN) == -1) {
		pcap_perror(handle, "set derection");
		return 3;
	}

	link_type = pcap_datalink(handle);

	printf("pcap data link type: %s\n", \
			pcap_datalink_val_to_name(link_type));

	init_send_buff(buff, link_type, sizeof(buff));

#if defined(__linux__)
	int one = 1;
	if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		err(EXIT_FAILURE, "socket(SOCK_RAW)");
	if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, \
				&one, sizeof(one)) == -1)
		err(EXIT_FAILURE, "setsockopt(IP_HDRINCL)");
#endif

	/* Looping grab packets */
	pcap_loop(handle, 0, act, NULL);
	/* And close the session */
	pcap_close(handle);
#if defined(__linux__)
	close(raw_socket);
#endif
	return(0);
}


