/*
 *  hexdump.c
 *
 *  Created by Summer Town on 9/16/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdint.h>		// uint8_t
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Notice: hex2ascii convert hex to ascii from inbuff to outbuff 
 * no more than inlen bytes and outlen bytes
 * outbuff is ended with '\0'
 * we suggest outlen is inlen * (3 + 1 / 16) + 1
 */
int
hex2ascii(char outbuff[], size_t outlen, const void *inbuff, size_t inlen)
{
	char *p = outbuff;
	size_t i;
	for (i = 0; i < (outlen << 4) / 49 && i < inlen; i++) {	// (outlen - 1) * 16 / 49
		if (i != 0) {
			size_t t = i % 16;
			if (t == 8)
				p += sprintf(p, "  ");
			else if (t == 0)
				p += sprintf(p, "\n");
			else
				p += sprintf(p, " ");
		}
		p += sprintf(p, "%02hhx", *((uint8_t *)inbuff++));
	}
	return p - outbuff;
}

void
hexdump(const void *data, size_t len)
{
	size_t bufflen = sizeof(char) * (len * 3 + len / 16 + 1);
	char *buff = (char *)malloc(bufflen);
	if (buff == NULL) {
		perror("Error: hexdump() malloc");
		return;
	}

	hex2ascii(buff, bufflen, data, len);

	fprintf(stderr, "%s\n", buff);
	free(buff);
}



