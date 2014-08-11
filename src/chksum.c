#include <sys/types.h>

u_int32_t
chksum(u_int16_t *p, u_int32_t sum, u_int len)
{
	int nwords = len >> 1;
	while (nwords-- != 0)
		sum += *p++;

	if (len & 1) {
		union {
			u_short w;
			u_char c[2];
		} u;
		u.c[0] = *(u_char *)p;
		u.c[1] = 0;
		sum += u.w;
	}

	return sum;
}

u_int16_t
final_sum(u_int32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

u_int16_t
in_cksum(u_int16_t *p, u_int len)
{
	u_int32_t sum = 0;
	sum = chksum(p, sum, len);
	return final_sum(sum);
}


