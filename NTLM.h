#pragma once

#define MAX_HOSTLEN 32
#define MAX_DOMLEN 32
#define MAX_USERLEN 32
#define RESP_LEN 24
#define NONCE_LEN 8

#define MAX_PSWLEN 32

/* fhz, 01-10-15 : borrowed from samba code */
/* NTLMSSP negotiation flags */
#define NTLMSSP_NEGOTIATE_UNICODE          0x00000001
#define NTLMSSP_NEGOTIATE_OEM              0x00000002
#define NTLMSSP_REQUEST_TARGET             0x00000004
#define NTLMSSP_NEGOTIATE_SIGN             0x00000010
#define NTLMSSP_NEGOTIATE_SEAL             0x00000020
#define NTLMSSP_NEGOTIATE_LM_KEY           0x00000080
#define NTLMSSP_NEGOTIATE_NTLM             0x00000200
#define NTLMSSP_NEGOTIATE_00001000         0x00001000
#define NTLMSSP_NEGOTIATE_00002000         0x00002000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN      0x00008000
#define NTLMSSP_TARGET_TYPE_DOMAIN	   0x00010000
#define NTLMSSP_TARGET_TYPE_SERVER	   0x00020000
#define NTLMSSP_NEGOTIATE_NTLM2            0x00080000
#define NTLMSSP_NEGOTIATE_TARGET_INFO      0x00800000
#define NTLMSSP_NEGOTIATE_128              0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH         0x40000000

#define SMBD_NTLMSSP_NEG_FLAGS 0x000082b1
#define NTLM_NTLMSSP_NEG_FLAGS 0x00008206
/* 8201 8207 */

#define LEN_NTLMSSP_FLAGS 4
#define OFFSET_MSG1_NTLMSSP_FLAGS 12

typedef unsigned char byte;

struct ntlm_msg1 {
    unsigned char protocol[8];
    unsigned char type;         /* 1 */
    unsigned char zero1[3];
    unsigned char flags[4];

    unsigned char dom_len[4];
    unsigned char dom_off[4];
	
    unsigned char host_len[4];
    unsigned char host_off[4];
	
}; /*__attribute__((packed))*/

struct ntlm_msg2 {
	byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
    byte    type;            // 0x02
    byte    zero1[7];
    short   msg_len;         // 0x28
    byte    zero2[2];
    byte    flags[4];
    byte    nonce[8];        // nonce
    byte    zero4[8];

};

struct ntlm_msg3 {
	byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
    byte    type;            // 0x03
    byte    zero1[3];

    short   lm_resp_len1;     // LanManager response length (always 0x18)
    short   lm_resp_len2;     // LanManager response length (always 0x18)
    short   lm_resp_off;     // LanManager response offset
    byte    zero2[2];

    short   nt_resp_len1;     // NT response length (always 0x18)
    short   nt_resp_len2;     // NT response length (always 0x18)
    short   nt_resp_off;     // NT response offset
    byte    zero3[2];

    short   dom_len1;         // domain string length
    short   dom_len2;         // domain string length
    short   dom_off;         // domain string offset (always 0x40)
    byte    zero4[2];

    short   user_len1;        // username string length
    short   user_len2;        // username string length
    short   user_off;        // username string offset
    byte    zero5[2];

    short   host_len1;        // host string length
    short   host_len2;        // host string length
    short   host_off;        // host string offset
    byte    zero6[6];

    short   msg_len;         // message length
    byte    zero7[2];

    byte   flags[2];           // 0x05,0x82,0x88,0xa2,5,1,40,10,0,0,0,15
    byte   zero8[2];


};

struct ntlm_msg2_win9x {
    unsigned char protocol[8];
    unsigned char type;         /* 2 */
    unsigned char zero1[3];
    unsigned char dom_len1[2];
    unsigned char dom_len2[2];
    unsigned char dom_off[4];
    unsigned char flags[2];
    unsigned char zero2[2];

    unsigned char nonce[8];
    unsigned char zero3[8];
    unsigned char zero4[4];
    unsigned char msg_len[4];
    unsigned char dom[MAX_DOMLEN];
};

/* size without dom[] : */
#define NTLM_MSG2_WIN9X_FIXED_SIZE (sizeof(struct ntlm_msg2_win9x)-MAX_DOMLEN)


typedef struct ntlmssp_info {
    int msg_type;
    unsigned char user[MAX_USERLEN + 1];
    unsigned char host[MAX_HOSTLEN + 1];
    unsigned char domain[MAX_DOMLEN + 1];
    unsigned char lm[RESP_LEN];
    unsigned char nt[RESP_LEN];
} ntlmssp_info_rec;


#define little_endian_word(x) x[0] + (((unsigned)x[1]) << 8)
/* fhz 02-02-09: typecasting is needed for a generic use */
#define set_little_endian_word(x,y) (*((char *)x))=(y&0xff);*(((char*)x)+1)=((y>>8)&0xff)
static int encode[] =
{
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};
