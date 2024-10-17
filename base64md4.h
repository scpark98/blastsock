#pragma once

#include "stdafx.h"

static const unsigned char pr2six[256] =
{
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54,
    55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static const char basis_64[]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


static void  uudecode_binary(/*apr_pool_t * p,*/char * bufplain, const char *bufcoded, int *nbytesdecoded)
{
    const unsigned char *bufin;
   
    unsigned char *bufout;
    int nprbytes;

    /* Strip leading whitespace. */

    while (*bufcoded == ' ' || *bufcoded == '\t')
        bufcoded++;

    /* Figure out how many characters are in the input buffer.
     * Allocate this many from the per-transaction pool for the
     * result. */
#ifndef CHARSET_EBCDIC
    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63) ;
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    *nbytesdecoded = ((nprbytes + 3) / 4) * 3;

   // bufplain = apr_palloc(p, *nbytesdecoded + 1);
    bufout = (unsigned char *) bufplain;

    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 0) {
        *(bufout++) =
            (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) =
            (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) =
            (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }

    if (nprbytes & 03) {
        if (pr2six[bufin[-2]] > 63)
            *nbytesdecoded -= 2;
        else
            *nbytesdecoded -= 1;
    }
    bufplain[*nbytesdecoded] = '\0';
#else /* CHARSET_EBCDIC */
    bufin = (const unsigned char *) bufcoded;
    while (pr2six[os_toascii[(unsigned char) *(bufin++)]] <= 63) ;
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    *nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufplain = apr_palloc(p, *nbytesdecoded + 1);
    bufout = (unsigned char *) bufplain;

    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 0) {
        *(bufout++)
            = os_toebcdic[(unsigned char) (pr2six[os_toascii[*bufin]]
                                           << 2 | pr2six[os_toascii[bufin[1]]]
                                           >> 4)];
        *(bufout++)
            = os_toebcdic[(unsigned char) (pr2six[os_toascii[bufin[1]]]
                                           << 4 | pr2six[os_toascii[bufin[2]]]
                                           >> 2)];
        *(bufout++)
            = os_toebcdic[(unsigned char) (pr2six[os_toascii[bufin[2]]]
                                         << 6 | pr2six[os_toascii[bufin[3]]])];
        bufin += 4;
        nprbytes -= 4;
    }

    if (nprbytes & 03) {
        if (pr2six[os_toascii[bufin[-2]]] > 63)
            *nbytesdecoded -= 2;
        else
            *nbytesdecoded -= 1;
    }
    bufplain[*nbytesdecoded] = '\0';
#endif /* CHARSET_EBCDIC */
    //return bufplain;
}

static  int uuencode_binary(char *encoded, unsigned char *string, int len)
{

	  const unsigned char *s, *end;
	  unsigned char *buf;
	  unsigned int x;
	  int n;
	  int i, j;
	
	  if (len == 0)
	    return 0;
	
	  end = (const unsigned char *)((char *)string + len - 3);
	
	  buf = (unsigned char *)malloc (4 * ((len + 2) / 3) + 1);
	  if (buf == NULL)
	    return -1;
	
	  n = 0;
	
	  for (s = (const unsigned char *)string; s < end;)
	    {
	      x = *s++ << 24;
	      x |= *s++ << 16;
	      x |= *s++ << 8;
	
	      *buf++ = encode[x >> 26];
	      x <<= 6;
	      *buf++ = encode[x >> 26];
	      x <<= 6;
	      *buf++ = encode[x >> 26];
	      x <<= 6;
	      *buf++ = encode[x >> 26];
	      n += 4;
	    }
	
	  end += 3;
	
	  x = 0;
	  for (i = 0; s < end; i++)
	    x |= *s++ << (24 - 8 * i);
	
	  for (j = 0; j < 4; j++)
	    {
	      if (8 * i >= 6 * j)
		{
		  *buf++ = encode [x >> 26];
		  x <<= 6;
		  n++;
		}
	      else
		{
		  *buf++ = '=';
		  n++;
		}
	    }
	
	  *buf = 0;
	
	  //encoded = (char*)(buf - n);
	  memcpy( encoded,buf-n,n);
	  return n;
//    int i;
//    char *p;
//     
//
//    p = encoded;
//#ifndef CHARSET_EBCDIC
//    for (i = 0; i < len - 2; i += 3) {
//        *p++ = basis_64[(string[i] >> 2) & 0x3F];
//        *p++ = basis_64[((string[i] & 0x3) << 4)
//                       | ((int) (string[i + 1] & 0xF0) >> 4)];
//        *p++ = basis_64[((string[i + 1] & 0xF) << 2)
//                       | ((int) (string[i + 2] & 0xC0) >> 6)];
//        *p++ = basis_64[string[i + 2] & 0x3F];
//    }
//    if (i < len) {
//        *p++ = basis_64[(string[i] >> 2) & 0x3F];
//        *p++ = basis_64[((string[i] & 0x3) << 4)
//                       | ((int) (string[i + 1] & 0xF0) >> 4)];
//        if (i == (len - 2))
//            *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
//        else
//            *p++ = '=';
//        *p++ = '=';
//    }
//#else /* CHARSET_EBCDIC */
//    for (i = 0; i < len - 2; i += 3) {
//        *p++ = basis_64[(os_toascii[string[i]] >> 2) & 0x3F];
//        *p++ = basis_64[((os_toascii[string[i]] & 0x3) << 4)
//                       | ((int) (os_toascii[string[i + 1]] & 0xF0) >> 4)];
//        *p++ = basis_64[((os_toascii[string[i + 1]] & 0xF) << 2)
//                       | ((int) (os_toascii[string[i + 2]] & 0xC0) >> 6)];
//        *p++ = basis_64[os_toascii[string[i + 2]] & 0x3F];
//    }
//    if (i < len) {
//        *p++ = basis_64[(os_toascii[string[i]] >> 2) & 0x3F];
//        *p++ = basis_64[((os_toascii[string[i]] & 0x3) << 4)
//                       | ((int) (os_toascii[string[i + 1]] & 0xF0) >> 4)];
//        if (i == (len - 2))
//            *p++ = basis_64[((os_toascii[string[i + 1]] & 0xF) << 2)];
//        else
//            *p++ = '=';
//        *p++ = '=';
//    }
//#endif /* CHARSET_EBCDIC */
//
//    *p = '\0';
//    return strlen( p );
}