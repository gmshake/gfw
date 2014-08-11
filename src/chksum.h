#ifndef CHKSUM_H
#define CHKSUM_H

u_int32_t chksum(u_int16_t *p, u_int32_t sum, u_int len);
u_int16_t final_sum(u_int32_t sum);
u_int16_t in_cksum(u_int16_t *p, u_int len);

#endif
