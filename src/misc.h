#ifndef MISC_H
#define MISC_H

struct pppheader {
	u_char ppp_addr;
	u_char ppp_ctrl;
	u_short ppp_proto;
};

struct tcp_pshdr {
	struct in_addr ip_src;
	struct in_addr ip_dst;
	u_char padding;
	u_char protocol;
	u_short length;
};

#endif
