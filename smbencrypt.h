#pragma once

#include "smades.h"

#define CVAL(buf,pos) (((unsigned char *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))
#define SCVAL(buf,pos,val) (CVAL(buf,pos) = (val))

#if CAREFUL_ALIGNMENT
#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#define IVAL(buf,pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#define SSVALX(buf,pos,val) (CVAL(buf,pos)=(val)&0xFF,CVAL(buf,pos+1)=(val)>>8)
#define SIVALX(buf,pos,val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#define SVALS(buf,pos) ((int16)SVAL(buf,pos))
#define IVALS(buf,pos) ((int32)IVAL(buf,pos))
#define SSVAL(buf,pos,val) SSVALX((buf),(pos),((uint16)(val)))
#define SIVAL(buf,pos,val) SIVALX((buf),(pos),((uint32)(val)))
#define SSVALS(buf,pos,val) SSVALX((buf),(pos),((int16)(val)))
#define SIVALS(buf,pos,val) SIVALX((buf),(pos),((int32)(val)))
#else
/* this handles things for architectures like the 386 that can handle
 * alignment errors */
/* 
 * WARNING: This section is dependent on the length of int16 and int32
 * being correct  */
#define SVAL(buf,pos) (*(uint16 *)((char *)(buf) + (pos)))
#define IVAL(buf,pos) (*(uint32 *)((char *)(buf) + (pos)))
#define SVALS(buf,pos) (*(int16 *)((char *)(buf) + (pos)))
#define IVALS(buf,pos) (*(int32 *)((char *)(buf) + (pos)))
#define SSVAL(buf,pos,val) SVAL(buf,pos)=((uint16)(val))
#define SIVAL(buf,pos,val) IVAL(buf,pos)=((uint32)(val))
#define SSVALS(buf,pos,val) SVALS(buf,pos)=((int16)(val))
#define SIVALS(buf,pos,val) IVALS(buf,pos)=((int32)(val))
#endif

void ABN_strupper(char *string)
{
	while (*string) {
		*string = toupper(*string);
		string++;
		}
}

/* Routines for Windows NT MD4 Hash functions. */
static int _my_wcslen(int16 *str)
{
	int len = 0;
	while(*str++ != 0)
		len++;
	return len;
}

/*
 * Convert a string into an NT UNICODE string.
 * Note that regardless of processor type 
 * this must be in intel (little-endian)
 * format.
 */
static int _my_mbstowcs(int16 *dst, uchar *src, int len)
{
	int i;
	int16 val;
 
	for(i = 0; i < len; i++) {
		val = *src;
		SSVAL(dst,0,val);
		dst++;
		src++;
		if(val == 0)
			break;
	}
	return i;
}

/* 
 * Creates the MD4 Hash of the users password in NT UNICODE.
 */
static void ABN_E_md4hash(uchar *passwd, uchar *p16)
{
	int len;
	int16 wpwd[129];
	
	/* Password cannot be longer than 128 characters */
	len = strlen((char *)passwd);
	if(len > 128)
		len = 128;
	/* Password must be converted to NT unicode */
	_my_mbstowcs(wpwd, passwd, len);
	wpwd[len] = 0; /* Ensure string is null terminated */
	/* Calculate length in bytes */
	len = _my_wcslen(wpwd) * sizeof(int16);

	ABN_mdfour(p16, (unsigned char *)wpwd, len);
}

/* Does both the NT and LM owfs of a user's password */
static void ABN_nt_lm_owf_gen(char *pwd, uchar nt_p16[16], uchar p16[16])
{
	char passwd[130];

	memset(passwd,'\0',130);
	/* safe strcpy() */
	if (strlen(pwd) > sizeof(passwd) - 1)
		pwd[sizeof(passwd) - 1] = '\0';
	strcpy( passwd, pwd);


	/* Calculate the MD4 hash (NT compatible) of the password */
	memset(nt_p16, '\0', 16);
	ABN_E_md4hash((uchar *)passwd, nt_p16);

	/* Mangle the passwords into Lanman format */
	passwd[14] = '\0';
	ABN_strupper(passwd);

	/* Calculate the SMB (lanman) hash functions of the password */

	memset(p16, '\0', 16);
	ABN_E_P16((uchar *) passwd, (uchar *)p16);

	/* clear out local copy of user's password (just being paranoid). */
	memset(passwd, '\0', sizeof(passwd));
}