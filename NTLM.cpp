#include "StdAfx.h"
#include "ntlm.h"
#include "base64md4.h"
#include "smades.h"
#include "smbencrypt.h"
#include "AllNTLM.h"
#include "common.h"
NTLM::NTLM(void)
{
	memset( username,0,sizeof(username) ) ;
	memset( psw,0,sizeof(psw) );
	memset( myhostname,0,sizeof( myhostname ) );
	memset( domain,0,sizeof( domain ) );
	memset( nounce,0,sizeof( nounce ) );
	memset( lm,0,sizeof(lm ) );
	memset( nt,0,sizeof(nt) );
}

NTLM::~NTLM(void)
{
}

int NTLM::ntlm_msg_type(unsigned char *raw_msg, unsigned msglen)
{
    struct ntlm_msg1 *msg = (struct ntlm_msg1 *) raw_msg;

    if (msglen < 9)
        return -1;
    if (strncmp((const char *)msg->protocol, "NTLMSSP", 8))
        return -1;
    return msg->type;
}

int NTLM::ntlm_extract_mem( unsigned char *dst,
                 unsigned char *src, unsigned srclen,
                 unsigned char *off, unsigned char *len,
                 unsigned max)
{
    unsigned o = *off/*little_endian_word(off)*/;
    unsigned l = *len/*little_endian_word(len)*/;
    if (l > max)
        return -1;
    if (o >= srclen)
        return -1;
    if (o + l > srclen)
        return -1;
    src += o;
    while (l-- > 0)
        *dst++ = *src++;
    return 0;
}

int NTLM::ntlm_extract_string( unsigned char *dst,
                    unsigned char *src, unsigned srclen,
                    unsigned char *off, unsigned char *len,
                    unsigned max)
{
	unsigned o = *off/*little_endian_word(off)*/;
    unsigned l = *len/*little_endian_word(len)*/;
    if (l > max)
        return -1;
    if (o >= srclen)
        return -1;
    if (o + l > srclen)
        return -1;
    src += o;
    while (l-- > 0) {
        /* +csz 2003/02/20 - En algunos casos vienen \0 entremedio */
        if ( *src != '\0' ) {
            *dst = *src;
            dst++;
        }
        src++;
    }
    *dst = 0;
    return 0;
}

int NTLM::ntlm_create_msg1( char * msgbuf, int * len) 
{
	char tbuf[1024];
	memset( tbuf,0,sizeof( tbuf ) );
	memset( msgbuf,0,*len );

	int retlen = 0;
	
	ntlm_msg1 * msg1 = (ntlm_msg1 * )tbuf;
	memcpy( msg1->protocol, "NTLMSSP",sizeof("NTLMSSP"));
	msg1->type = 1;
	msg1->flags[ 0 ]= 0x03;
	msg1->flags[ 1 ]= 0xb2;

	int host_len = strlen( myhostname );
	int dom_len = strlen(domain);

	set_little_endian_word( msg1->host_len,host_len ); 
	set_little_endian_word( msg1->host_len+2,host_len );

	set_little_endian_word( msg1->host_off, 32 );

	set_little_endian_word( msg1->dom_len,dom_len ); 
	set_little_endian_word( msg1->dom_len+2,dom_len );

	int dom_off = 32 + host_len;
	set_little_endian_word( msg1->dom_off,dom_off );

	memcpy( tbuf + 32, myhostname,host_len );
	memcpy( tbuf + dom_off, domain,dom_len );

	retlen = dom_off + dom_len;
	
	uuencode_binary( msgbuf, (unsigned char*)tbuf,retlen);

	retlen = strlen( msgbuf );
	return retlen;
}

int NTLM::ntlm_extract_msg2( char * msgbuf, int * len)
{
	char tbuf[512];
	memset( tbuf,0,sizeof(tbuf) );
	int ndecodedlen = 0;
	uudecode_binary( tbuf, msgbuf, &ndecodedlen );
	ntlm_msg2 * msg2 = (ntlm_msg2 *)tbuf;
	memcpy( this->nounce, msg2->nonce,8);
	memcpy( this->msg2flags, msg2->flags,4);
	return 1;
}


int NTLM::ntlm_create_msg3( char * msgbuf, int * len)
{
	int16 domain16[ MAX_DOMLEN + 1];
	int16 myhostname16[ MAX_HOSTLEN + 1];
	int16 username16[ MAX_USERLEN + 1];
	int16 psw16[33];
	memset( domain16,0,sizeof(domain16) );
	memset( myhostname16,0,sizeof(myhostname) );
	memset( username16,0,sizeof(username) );
	memset( psw16,0,sizeof(psw16) );
	_my_mbstowcs( domain16,(uchar*)domain,strlen(domain) );
	_my_mbstowcs( myhostname16,(uchar*)myhostname,strlen(myhostname) );
	_my_mbstowcs( username16,(uchar*)username,strlen(username) );
	_my_mbstowcs( psw16,(uchar*)psw,strlen(psw) );
	char tbuf[1024];
	memset( tbuf,0,sizeof( tbuf ) );
	memset( msgbuf,0,*len );

	int retlen = 0;
	
	ntlm_msg3 * msg3 = (ntlm_msg3 * )tbuf;
	memcpy( msg3->protocol, "NTLMSSP",sizeof("NTLMSSP"));
	msg3->type = 3;
	msg3->lm_resp_len1 = 0x18;
	msg3->lm_resp_len2 = 0x18;

	msg3->nt_resp_len1 = 0x18;
	msg3->nt_resp_len2 = 0x18;

	msg3->dom_len1 = strlen( domain )*2;
	msg3->dom_len2 = strlen( domain )*2;

	msg3->user_len1 = strlen( username )*2;
	msg3->user_len2 = strlen( username )*2;

	msg3->host_len1 = strlen( myhostname )*2;
	msg3->host_len2 = strlen( myhostname )*2;
	
	msg3->flags[0] = 0x01;
	msg3->flags[1] = 0x82;

	uchar t_lm[21];
	uchar t_nt[21];
	ABN_nt_lm_owf_gen( psw, t_nt, t_lm );
	memset( t_lm+16,0,5);
	memset( t_nt+16,0,5);

	ABN_E_P24( t_nt, nt,  this->nounce );
	ABN_E_P24( t_lm, lm,  this->nounce );
	


	msg3->dom_off = 64;
	msg3->user_off = 64 + msg3->dom_len1;
	msg3->host_off = 64 + + msg3->dom_len1 + msg3->user_len1 ;
	msg3->lm_resp_off = 64 + + msg3->dom_len1 + msg3->user_len1 + msg3->host_len1;
	msg3->nt_resp_off = 64 + + msg3->dom_len1 + msg3->user_len1 + msg3->host_len1 + msg3->lm_resp_len1;

	unsigned char enkey[8];
    unsigned char cread[0x40];
    unsigned char passwordhash[0x20];
    unsigned char creaded[0x100];

	memcpy( challage,nounce,8);
	//wchar_t
	passtoowf( /*L"123456"*/(wchar_t*)psw16,passwordhash);   
	
    challagetorkey(romkey,nounce,enkey);   
    memset(cread,0,0x40);
    memcpy(cread,romkey,0x8);   
    hashtocread(enkey,passwordhash,cread);   
    
	
	

	memcpy( tbuf + msg3->dom_off, domain16, msg3->dom_len1 );
	memcpy( tbuf + msg3->user_off, username16, msg3->user_len1 );
	memcpy( tbuf + msg3->host_off, myhostname16, msg3->host_len1 );
	memcpy( tbuf + msg3->lm_resp_off, lm, msg3->lm_resp_len1 );
	memcpy( tbuf + msg3->nt_resp_off, nt, msg3->nt_resp_len1 );
	//memcpy(tbuf + msg3->lm_resp_off,cread,0x30); 

	retlen = msg3->nt_resp_off + msg3->nt_resp_len1;
	msg3->msg_len = retlen;
	uuencode_binary( msgbuf, (unsigned char*)tbuf,retlen);

	retlen = strlen( msgbuf );
	
	return retlen;


}




