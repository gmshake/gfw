/*
 *  hexdump.h
 *
 *  Created by Summer Town on 9/16/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _HEXDUMP_H
#define _HEXDUMP_H

extern void hexdump(const void *data, size_t len);
extern int hex2ascii(char out[], size_t outlen, const void *in, size_t inlen);

#endif
