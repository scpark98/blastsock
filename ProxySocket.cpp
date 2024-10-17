// ProxySocket.cpp: implementation of the CProxySocket class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "stdio.h"
#include "ProxySocket.h"
#include "base64.h"
#include "WinINetDownLoader.h"
#include "NTLM.h"
#include "AllNTLM.h"
#include "md4.h"
#include "md5c.h"
#include "smbencrypt.h"


//MD5 Implementation
#define S11		7
#define S12		12
#define S13		17
#define S14		22
#define S21		5
#define S22		9
#define S23		14
#define S24		20
#define S31		4
#define S32		11
#define S33		16
#define S34		23
#define S41		6
#define S42		10
#define S43		15
#define S44		21


void MD5Transform(UINT4[4], unsigned char[64]);
void Encode(unsigned char *, UINT4 *, unsigned int);
void Decode(UINT4 *, unsigned char *, unsigned int);
void MD5_memcpy(POINTER, POINTER, unsigned int);
void MD5_memset(POINTER, int, unsigned int);


static unsigned char PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
*/
#ifndef MD5_F
#define MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#endif

#ifndef MD5_G
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#endif

#ifndef MD5_H
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#endif

#ifndef MD5_I
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))
#endif



/* ROTATE_LEFT rotates x left n bits.
*/
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
*/
#define FF(a, b, c, d, x, s, ac) { \
	(a) += MD5_F ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}
#define GG(a, b, c, d, x, s, ac) { \
	(a) += MD5_G ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}
#define HH(a, b, c, d, x, s, ac) { \
	(a) += MD5_H ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}
#define II(a, b, c, d, x, s, ac) { \
	(a) += MD5_I ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}

#define EPOCHDELTA	(ULONGLONG)(116444736000000000)
//* end of MD5 

unsigned int	TIMER_GetTimeInMilliseconds(void);

unsigned int	TIMER_GetTimeInMilliseconds(void)
{
	unsigned int t;
	SYSTEMTIME	systime;
	FILETIME	filetime;
	ULARGE_INTEGER	*uint_time;

	GetSystemTime(&systime);
	SystemTimeToFileTime(&systime, &filetime);

	uint_time = (ULARGE_INTEGER *)&filetime;
	uint_time->QuadPart = uint_time->QuadPart - EPOCHDELTA;

	t = (unsigned int)(uint_time->QuadPart / 10000Ui64);

	return (t == 0xffffffff) ? 0 : t;
}


static const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

static void encodeblock(unsigned char in[3], unsigned char out[4], int len)
{
	out[0] = cb64[in[0] >> 2];
	out[1] = cb64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
	out[2] = (unsigned char)(len > 1 ? cb64[((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)] : '=');
	out[3] = (unsigned char)(len > 2 ? cb64[in[2] & 0x3f] : '=');
}

void base64(char *dst, const char *src, int sz)
{
	unsigned char in[3];
	unsigned char *out = (unsigned char*)dst;
	int i, len;

	while (sz > 0)
	{
		len = 0;
		for (i = 0; i < 3; i++, sz--)
		{
			if (sz > 0)
			{
				len++;
				in[i] = src[i];
			}
			else
				in[i] = 0;
		}
		src += 3;
		if (len)
		{
			encodeblock(in, out, len);
			out += 4;
		}
	}
	*out = '\0';
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

	buf = (unsigned char *)malloc(4 * ((len + 2) / 3) + 1);
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
			*buf++ = encode[x >> 26];
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
	memcpy(encoded, buf - n, n);
	return n;
}

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
	bufin = (const unsigned char *)bufcoded;
	while (pr2six[*(bufin++)] <= 63);
	nprbytes = (bufin - (const unsigned char *)bufcoded) - 1;
	*nbytesdecoded = ((nprbytes + 3) / 4) * 3;

	// bufplain = apr_palloc(p, *nbytesdecoded + 1);
	bufout = (unsigned char *)bufplain;

	bufin = (const unsigned char *)bufcoded;

	while (nprbytes > 0) {
		*(bufout++) =
			(unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
		*(bufout++) =
			(unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
		*(bufout++) =
			(unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
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
	bufin = (const unsigned char *)bufcoded;
	while (pr2six[os_toascii[(unsigned char) *(bufin++)]] <= 63);
	nprbytes = (bufin - (const unsigned char *)bufcoded) - 1;
	*nbytesdecoded = ((nprbytes + 3) / 4) * 3;

	bufplain = apr_palloc(p, *nbytesdecoded + 1);
	bufout = (unsigned char *)bufplain;

	bufin = (const unsigned char *)bufcoded;

	while (nprbytes > 0) {
		*(bufout++)
			= os_toebcdic[(unsigned char)(pr2six[os_toascii[*bufin]]
				<< 2 | pr2six[os_toascii[bufin[1]]]
				>> 4)];
		*(bufout++)
			= os_toebcdic[(unsigned char)(pr2six[os_toascii[bufin[1]]]
				<< 4 | pr2six[os_toascii[bufin[2]]]
				>> 2)];
		*(bufout++)
			= os_toebcdic[(unsigned char)(pr2six[os_toascii[bufin[2]]]
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





USING_NAMESPACE(CryptoPP)
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

ProxySocket::ProxySocket() : Socket()
{
}
	
ProxySocket::~ProxySocket()
{
}

void ProxySocket::SetProxyData(CProxyData& ProxyData)
{
	m_ProxyData = ProxyData;
}

bool ProxySocket::Connect(char *addr, unsigned int port)
{
	Socket::CloseSocket();
	Socket::Create();

	bool result = false;

	switch(m_ProxyData.GetType())
	{
	case PROXYTYPE_NOPROXY:
		Socket::PrintLog(4 , "ProxySocket::Connect(%s , %d) (PROXYTYPE_NOPROXY) Start\r\n" , addr , port);
		result = ConnectNOPROXY(addr, port);
		break;
	case PROXYTYPE_SOCKS4:
	case PROXYTYPE_SOCKS4A:
		Socket::PrintLog(4 , "ProxySocket::Connect(%s , %d) (PROXYTYPE_SOCKS4) Start\r\n" , addr , port);
		result = ConnectSOCKS4(addr, port);
		break;
	case PROXYTYPE_SOCKS5:
		Socket::PrintLog(4 , "ProxySocket::Connect(%s , %d) (PROXYTYPE_SOCKS5) Start\r\n" , addr , port);
		result = ConnectSOCKS5(addr, port);
		break;
	case PROXYTYPE_HTTP11:
	case PROXYTYPE_HTTP11QUERY:
		Socket::PrintLog(4 , "ProxySocket::Connect(%s , %d) (PROXYTYPE_HTTP11) Start\r\n" , addr , port);
		result = ConnectHTTP11(addr, port);

		if (result == false)
		{
			//2)SOCKS4
			result = ConnectSOCKS4(addr, port);
		}

		if (result) //SOCKS4 성공시 
			break;

		//3)SOCKS5로 시도
		result = ConnectSOCKS5(addr, port);
		
		break;
	}
	
	if(!result) 
	{
		Socket::PrintLog(5 , "[Error]Failt to Connect ProxySocket::Connect() End\r\n" );
		CloseSocket();
	}
	else
	{
		Socket::PrintLog(5 , "Success to Connect ProxySocket::Connect() End\r\n" );
	}

	return result;
}

bool ProxySocket::ConnectNOPROXY(char *addr, unsigned int port)
{
	
	Socket::PrintLog(5 , "ProxySocket::ConnectNOPROXY(%s , %d) Start\r\n" , addr , port);
	if(Socket::Connect(addr, port)) return true;
	WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
	return false;
}

bool ProxySocket::ConnectSOCKS4(char *addr, unsigned int port)
{
	Socket::PrintLog(5 , "ProxySocket::ConnectSOCKS4(%s , %d) Start\r\n" , addr , port);
	Socket::PrintLog(5 , "Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());

	if(!Socket::Connect(m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort()))
	{
		Socket::PrintLog(5 , "[Error]Fail Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());
		WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
		return false;
	}

	// Make request
	LPSTR lpRequestPacket = new CHAR[9+strlen(addr)+1];
	ZeroMemory(lpRequestPacket, 9+strlen(addr)+1);
	int len = 9;

	// VN is the SOCKS protocol version number and should be 4
	lpRequestPacket[0] = 4; 

	// CD is the SOCKS command code and shoule be 1 for CONNECT request
	lpRequestPacket[1] = 1; 

	// DSTPORT is the destination server's port number
	SHORT lpNBOPort = htons(port);
	memcpy(&lpRequestPacket[2], &lpNBOPort, 2);
		
	// DSTIP 
	// resolve the destination host's damain name
	LONG lInetAddr = Socket::Inet_Addr(addr);

	if(lInetAddr == INADDR_ANY)
	{
		// It allows only SOCKS 4A
		//if(m_ProxyData.GetType() != PROXYTYPE_SOCKS4A) 
		if(m_ProxyData.GetType() != PROXYTYPE_SOCKS4A && m_ProxyData.GetType() != PROXYTYPE_SOCKS4) 
		{
			Socket::PrintLog(5 , "[Error]m_ProxyData.GetType() != PROXYTYPE_SOCKS4A\r\n");
			delete [] lpRequestPacket;
			WSASetLastError(PROXYSOCKET_ERROR_CANTRESOLVEHOST);
			return false;
		}

		// If the client cannot resolve the destination host's domain name to find its IP address,
		// it should set the first three bytes of DSTIP to NULL and the last byte to a non-zero value
		// (This corresponds to IP address 0.0.0.x, with x nonzero.)
		lpRequestPacket[4] = 0;
		lpRequestPacket[5] = 0;
		lpRequestPacket[6] = 0;
		lpRequestPacket[7] = 1;
		
		// Following the NULL byte terminating USERID, 
		// the client must sends the destination domain name and terminates it with another NULL bytes.
		strcpy(&lpRequestPacket[9], addr);
		len += strlen(addr) + 1;
	}
	else
	{
		memcpy(&lpRequestPacket[4], &lInetAddr, 4);
	}
	
	// Send request
	Socket::PrintLog(5 , "Send  PROXYTYPE_SOCKS4 request\r\n");
	if(!SendExact(lpRequestPacket, len))
	{
		Socket::PrintLog(5 , "[error] Could not Send  PROXYTYPE_SOCKS4 request\r\n");
		delete [] lpRequestPacket;
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}
	delete [] lpRequestPacket;

	// Recv response
	char szResponsePacket[8];
	if(!RecvExact(szResponsePacket, 8))
	{
		Socket::PrintLog(5 , "[error] Could not Recv PROXYTYPE_SOCKS4 response\r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	Socket::PrintLog(5 , "Recv PROXYTYPE_SOCKS4 response\r\n");

	if(szResponsePacket[0] != 0)
	{	// VN is the version of the reply code and should be 0
		Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_REQUESTFAILED 1 \r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	if(szResponsePacket[1] != 90)
	{
		Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_REQUESTFAILED 2\r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		if(szResponsePacket[1] == 93) WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
		return false;
	}

	// request granted
	Socket::PrintLog(5 , "ProxySocket::ConnectSOCKS4() end .. request granted\r\n");
	return true;
}

bool ProxySocket::ConnectSOCKS5(char *addr, unsigned int port)
{
	Socket::PrintLog(5 , "ProxySocket::ConnectSOCKS5(%s , %d) Start\r\n" , addr , port);
	Socket::PrintLog(5 , "Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());


	if(!Socket::Connect(m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort()))
	{
		Socket::PrintLog(5 , "[Error]Fail Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());
		WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
		return false;
	}

	// Send initialization request
	BYTE lpBuffer[10];
	ZeroMemory(lpBuffer, 10);

	// VER is set to 5 for this version of the protocol
	lpBuffer[0] = 5;

	// NMETHOD
	lpBuffer[1] = m_ProxyData.GetAuth() ? 2 : 1;
	
	// METHODS , 2 = user/pass, 0 = no logon
	lpBuffer[2] = m_ProxyData.GetAuth() ? 2 : 0;

	// length of request
	int len = m_ProxyData.GetAuth() ? 4 : 3; 

	Socket::PrintLog(5 , "Send  PROXYTYPE_SOCKS5 request\r\n");
	if(!SendExact((LPCSTR)lpBuffer, len))
	{
		Socket::PrintLog(5 , "[error] Could not Send  PROXYTYPE_SOCKS5 request\r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	// response
	ZeroMemory(lpBuffer, 10);
	if(!RecvExact((LPSTR)lpBuffer, 2))
	{
		Socket::PrintLog(5 , "[error] Could not Recv PROXYTYPE_SOCKS5 response\r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	Socket::PrintLog(5 , "Recv PROXYTYPE_SOCKS5 response\r\n");

	if(lpBuffer[0] != 5)
	{
		Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_REQUESTFAILED 1 \r\n");

		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	if(lpBuffer[1] == 0xFF)
	{
		Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_AUTHFAILED 1 \r\n");

		if(m_ProxyData.GetAuth()) WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
		else WSASetLastError(PROXYSOCKET_ERROR_AUTHREQUIRED);
		return false;
	}

	if(lpBuffer[1])
	{	// Auth needed
		if(lpBuffer[1] != 2)
		{	// Unknown auth type
			Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_AUTHTYPEUNKNOWN 1 \r\n");
			WSASetLastError(PROXYSOCKET_ERROR_AUTHTYPEUNKNOWN);
			return false;
		}

		if(!m_ProxyData.GetAuth())
		{
			Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_AUTHNOLOGON 1 \r\n");
			WSASetLastError(PROXYSOCKET_ERROR_AUTHNOLOGON);
			return false;
		}
		
		// Send authentication
		LPBYTE buffer = new BYTE[3+strlen(m_ProxyData.GetUser())+strlen(m_ProxyData.GetPass())+1];
		sprintf((LPSTR)buffer, "  %s %s", m_ProxyData.GetUser(), m_ProxyData.GetPass());
		
		buffer[0] = 5;
		buffer[1] = static_cast<BYTE>(strlen(m_ProxyData.GetUser()));
		buffer[2 + strlen(m_ProxyData.GetUser())] = static_cast<BYTE>(strlen(m_ProxyData.GetPass()));

		int len = 3 + strlen(m_ProxyData.GetUser()) + strlen(m_ProxyData.GetPass());

		Socket::PrintLog(5 , "Send PROXYTYPE_SOCKS5 Authentication (%s , %s) \r\n" , m_ProxyData.GetUser() , m_ProxyData.GetPass());

		if(!SendExact((LPCSTR)buffer, len))
		{
			Socket::PrintLog(5 , "[Error] Could not Send PROXYTYPE_SOCKS5 Authentication (%s , %s) \r\n" , m_ProxyData.GetUser() , m_ProxyData.GetPass());
			delete [] buffer;
			WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
			return false;
		}
		delete [] buffer;

		// Response to the auth request
		if(!RecvExact((LPSTR)lpBuffer, 2))
		{
			Socket::PrintLog(5 , "[Error] Could not Recv PROXYTYPE_SOCKS5 Authentication Response \r\n");
			WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
			return false;
		}

		Socket::PrintLog(5 , "Recv PROXYTYPE_SOCKS5 Authentication Response \r\n" );
		
		if(lpBuffer[1] != 0)
		{
			Socket::PrintLog(5 , "[Error] PROXYSOCKET_ERROR_AUTHFAILED \r\n" );
			WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
			return false;
		}
	}

	// Send Connection Request
	LPSTR command = new CHAR[10 + strlen(addr)+1];
	ZeroMemory(command, 10 + strlen(addr) + 1);
	
	// VER  protocol version is 5
	command[0] = 5;
	
	// CMD  CONNECT = 1 , BIND = 2
	command[1] = 1;
	
	// RSV  RESERVED
	command[2] = 0;

	// ATYP  address type of following address	
	LONG lInetAddr = Socket::Inet_Addr(addr);
	command[3] = lInetAddr?1:3;

	// DST.ADDR desired destination address
	len = 4;
	if(lInetAddr)
	{
		memcpy(&command[len],&lInetAddr,4);
		len += 4;
	}
	else
	{
		command[len] = strlen(addr);
		strcpy(&command[len+1], addr);
		len += strlen(addr) + 1;
	}
	
	// DST.PORT desired destination port in network octet
	SHORT shNBOPort = htons(port);
	memcpy(&command[len], &shNBOPort, 2);
	len+=2;

	Socket::PrintLog(5 , "Send Desired destinatino port(%d) \r\n" , port );

	if(!SendExact(command,len))
	{
		Socket::PrintLog(5 , "[Error] Could not Send Desired destinatino port(%d) \r\n" , port );
		delete [] command;
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	// Response
	if(!RecvExact(command,10))
	{
		Socket::PrintLog(5 , "[Error] Could not recv Desired destinatino port response \r\n");
		delete [] command;
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}
	Socket::PrintLog(5 , "recv Desired destinatino port response \r\n");

	// Check for errors
	if (command[1] != 0 || command[0] != 5)
	{
		Socket::PrintLog(5 , "[Error] PROXYSOCKET_ERROR_REQUESTFAILED 3 \r\n");
		delete [] command;
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	Socket::PrintLog(5 , "ProxySocket::ConnectSOCKS5() End ... connection established OK\r\n");
	delete [] command;
	return true;
	// connection established OK
}


bool ProxySocket::ConnectHTTP11(char *host, unsigned int port)
{
	int result;

	Socket::PrintLog(5, "[SOCKET]ConnectHTTP11 Start (%s , %d)" , m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort() );

	if (!Socket::Connect(m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort()))
	{
		Socket::PrintLog(5, "[Error]Fail Socket::Connect to Proxy(%s , %d) \r\n", m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort());

		WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
		return false;
	}

	/*
	if (m_ProxyData.GetType() == PROXYTYPE_HTTP11QUERY)
	{
		Socket::PrintLog(5, "[Error] m_ProxyData.GetType() == PROXYTYPE_HTTP11QUERY \r\n");
		m_ProxyData.SetDestinationHost(host);
		m_ProxyData.SetDestinationPort(port);
		return true;
	}

	*/

	Socket::PrintLog(5, "[SOCKET] Success Connect  (%s , %d)", m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort());

	char buffer[4096] = { 0, };
	char temp[4096] = { 0, };

	sprintf(buffer,
		"CONNECT %s:%d HTTP/1.0\r\n"
		"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;"
		" SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 1.1.4322)\r\n"
		"Host: %s:%d\r\n"
		"Content-Length: 0\r\n"
		"Proxy-Connection: Keep-Alive\r\n"
		"Pragma: no-cache\r\n\r\n",
		host, port, host, port);


	Socket::PrintLog(5, "Send  PROXYTYPE_HTTP11 request \r\n");
	if (!SendExact(buffer, strlen(buffer)))
	{
		Socket::PrintLog(5, "[Error] Could not Send  PROXYTYPE_HTTP11 request \r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	ZeroMemory(buffer, sizeof(buffer));

	// recv Response
	if (!RecvUntil(buffer, 4096, "\r\n"))
	{
		Socket::PrintLog(5, "[Error] Could not recv  PROXYTYPE_HTTP11 response \r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	Socket::PrintLog(5, "%s\r\n", buffer);



	char *p = NULL;
	char *p2 = NULL;
	int len = 0;
	char szAuthCode[16] = { 0 , };

	p = strstr(buffer, " ");

	if (p == NULL)
		return false;

	p2 = strstr(p + 1, " ");

	if (p2 == NULL)
		return false;

	len = (unsigned int)p2 - ((unsigned int)p + 1);

	memcpy(szAuthCode, p + 1, len);
	DWORD dwStatusCode = atoi(szAuthCode);

	if (dwStatusCode == 200)
	{
		Socket::PrintLog(5, "[SOCKET]Success ConnectHTTP11 200OK");
		return true;
	}
	else if (dwStatusCode == 401 || dwStatusCode == 407)
	{
		//BASIC 인지 NTLM 인지 확인하여 인증정보를 넣어서 보낸다.
		p = NULL;
		p = strstr(buffer, "Proxy-Authenticate: ");

		if (p == NULL)
		{
			p = strstr(buffer, "proxy-authenticate: ");
		}

		if (p != NULL)
		{
			p2 = strstr(p, " ");

			if (p2 == NULL)
				return false;

			p = strstr(p2 + 1, "\r\n");

			if (p == NULL)
				return false;

			len = ((unsigned int)p - 2) - (unsigned int)p2 + 1;
			char header[1024];
			memset(header, 0, sizeof(header));
			memcpy(header, p2 + 1, len);
			header[len] = '\0';

			p = strstr((char*)&header[0], " ");

			if (p == NULL)
			{
				memset(szAuthCode, 0x00, sizeof(szAuthCode));
				memcpy(szAuthCode, (char*)&header[0], len);
			}
			else
			{
				len = (unsigned int)p - ((unsigned int)&header[0]);
				memset(szAuthCode, 0x00, sizeof(szAuthCode));
				memcpy(szAuthCode, (char*)&header[0], len);
			}
		}
		else
		{
			p = NULL;
			p = strstr(buffer, "Proxy-Authorization: ");

			if (p == NULL)
			{
				p = strstr(buffer, "proxy-authorization: ");
			}

			if (p != NULL)
			{
				p2 = strstr(p, " ");

				if (p2 == NULL)
					return false;

				p = strstr(p2 + 1, "\r\n");

				if (p == NULL)
					return false;

				len = ((unsigned int)p - 2) - (unsigned int)p2 + 1;
				char header[1024];
				memset(header, 0, sizeof(header));
				memcpy(header, p2 + 1, len);
				header[len] = '\0';

				p = strstr((char*)&header[0], " ");

				if (p == NULL)
				{
					memset(szAuthCode, 0x00, sizeof(szAuthCode));
					memcpy(szAuthCode, (char*)&header[0], len);
				}
				else
				{
					len = (unsigned int)p - ((unsigned int)&header[0]);
					memset(szAuthCode, 0x00, sizeof(szAuthCode));
					memcpy(szAuthCode, (char*)&header[0], len);
				}
			}
			else
			{
				return false;
			}
		}

		if (strcmp(szAuthCode, "Basic") == 0 || strcmp(szAuthCode, "basic") == 0)
		{
			CloseSocket();
			Create();

			if (!Socket::Connect(m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort()))
			{
				Socket::PrintLog(5, "[Error]Fail Socket::Connect to Proxy(%s , %d) \r\n", m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort());

				WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
				return false;
			}



			// Basic auth info
			char user_pass[512];
			char encoded[512];

			int wlen = _snprintf(user_pass, 512, "%s:%s", m_ProxyData.GetUser(), m_ProxyData.GetPass());
			base64(encoded, user_pass, wlen);

			ZeroMemory(buffer, sizeof(buffer));

			sprintf(buffer,
				"CONNECT %s:%d HTTP/1.0\r\n"
				"User-Agent: Mozilla/4.0(compatible;MSIE6.0;WindowsNT5.1;SV1;.NETCLR\r\n"
				"Host: %s:%d\r\n"
				"Content-Length: 0\r\n"
				"Proxy-Connection: Keep-Alive\r\n"
				"Pragma: no-cache\r\n"
				"Proxy-Authorization: Basic %s\r\n\r\n",
				host, port, host, port, (char*)encoded);
		}
		else if (strcmp(szAuthCode, "Digest") == 0 || strcmp(szAuthCode, "digest") == 0 || strcmp(szAuthCode, "DIGEST") == 0)
		{
			CloseSocket();
			Create();

			if (!Socket::Connect(m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort()))
			{
				Socket::PrintLog(5, "[Error]Fail Socket::Connect to Proxy(%s , %d) \r\n", m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort());

				WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
				return false;
			}

			//get realm , nonce , algorithm , qop , opaque
			MakeDigestResponse(buffer, host, port);

			ZeroMemory(buffer, sizeof(buffer));

			sprintf(buffer,
				"CONNECT %s:%d HTTP/1.0\r\n"
				"User-Agent: Mozilla/4.0(compatible;MSIE6.0;WindowsNT5.1;SV1;.NETCLR\r\n"
				"Host: %s:%d\r\n"
				"Content-Length: 0\r\n"
				"Proxy-Connection: Keep-Alive\r\n"
				"Pragma: no-cache\r\n"
				"Proxy-Authorization: Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%S:%d\",cnonce=\"%s\",nc=%08d,algorithm=MD5,response=\"%s\",qop=\"%s\",opaque=\"%s\""
				"\r\n\r\n",
				host, port, host, port, m_ProxyData.GetProxyHost(), m_szrealm, m_sznonce, host, port, m_szcnonce, m_nonceCount, m_szresponse, m_szqop, m_szopaque);

		}
		else if (strcmp(szAuthCode, "NTLM") == 0 || strcmp(szAuthCode, "Ntlm") == 0 || strcmp(szAuthCode, "ntlm") == 0)
		{

			CloseSocket();
			Create();

			if (!Socket::Connect(m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort()))
			{
				Socket::PrintLog(5, "[Error]Fail Socket::Connect to Proxy(%s , %d) \r\n", m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort());

				WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
				return false;
			}

			//NTLM PHASE1 , NTLMSSP_NEGOTIATE


			//NTLM auth Info
			char account[256];
			char username[256];
			char msgbuf[1024];
			int idx;
			int msgbuflen = sizeof(msgbuf);
			int msglen;

			ZeroMemory(account, sizeof(account));
			ZeroMemory(ntlm_domain, sizeof(ntlm_domain));
			ZeroMemory(username, sizeof(username));

			strcpy(account, m_ProxyData.GetUser());

			if (strstr(account, "\\") != NULL)
			{
				strcpy(ntlm_domain, strtok(account, "\\"));
				strcpy(username, strtok(NULL, "\\"));
			}
			else
			{
				strcpy(ntlm_domain, "DOMAIN");
				strcpy(username, account);
			}

			strcpy(ntlm_userid, username);
			strcpy(ntlm_userpw, m_ProxyData.GetPass());

			memset(ntlm_hostname, 0x00, sizeof(ntlm_hostname));
			::gethostname(ntlm_hostname, sizeof(ntlm_hostname));


			for (idx = 0; idx < strlen(ntlm_hostname); idx++)
			{
				if (ntlm_hostname[idx] >= 'a' && ntlm_hostname[idx] <= 'z')
					ntlm_hostname[idx] = ntlm_hostname[idx] - 'a' + 'A'; // to uppercase letter
			}

			msglen = create_NtlmSsp_Negotiate(msgbuf, &msgbuflen, ntlm_hostname, ntlm_domain);

			sprintf(buffer,
				"CONNECT %s:%d HTTP/1.0\r\n"
				"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;"
				" SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 1.1.4322)\r\n"
				"Host: %s:%d\r\n"
				"Content-Length: 0\r\n"
				"Proxy-Connection: Keep-Alive\r\n"
				"Pragma: no-cache\r\n"
				"Proxy-Authorization: NTLM %s\r\n\r\n",
				host, port, host, port, msgbuf);


			if (!SendExact(buffer, strlen(buffer)))
			{
				Socket::PrintLog(5, "[Error] Could not Send  PROXYTYPE_HTTP11 request \r\n");
				WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
				return false;
			}


			ZeroMemory(buffer, sizeof(buffer));

			//NTLMSSP_CHANGE를 받을 것이다.

			if (!RecvUntil(buffer, 4096, "\r\n"))
			{
				Socket::PrintLog(5, "[Error] Could not recv  PROXYTYPE_HTTP11 response \r\n");
				WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
				return false;
			}

			Socket::PrintLog(5, "%s\r\n", buffer);

			p = strstr(buffer, " ");

			if (p == NULL)
			{
				return false;
			}

			p2 = strstr(p + 1, " ");

			if (p2 == NULL)
			{
				return false;
			}

			len = (unsigned int)p2 - ((unsigned int)p + 1);

			memset(szAuthCode, 0x00, sizeof(szAuthCode));
			memcpy(szAuthCode, p + 1, len);

			dwStatusCode = atoi(szAuthCode);

			if (dwStatusCode == 200)
			{
				return true;
			}
			else if (dwStatusCode == 401 || dwStatusCode == 407)
			{
				//GET Change key
				len = strlen(msgbuf);
				GetNtlmSsp_Change_Key(msgbuf, buffer);
				GetNonceFromChange_Key(msgbuf, &len);

				if (strcmp((const char *)nounce, "") == 0)
				{
					return false;
				}

				msglen = Create_NtlmSsp_Auth(msgbuf, &msgbuflen);

				memset(buffer, 0x00, sizeof(buffer));

				sprintf(buffer,
					"CONNECT %s:%d HTTP/1.0\r\n"
					"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;"
					" SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 1.1.4322)\r\n"
					"Host: %s:%d\r\n"
					"Content-Length: 0\r\n"
					"Proxy-Connection: Keep-Alive\r\n"
					"Pragma: no-cache\r\n"
					"Proxy-Authorization: NTLM %s\r\n\r\n",
					host, port, host, port, msgbuf);
			}
		}
		else //BASIC , Digest , NTLM도 아닌 경우
		{

			return false;
		}
	}

	return true;
}


bool ProxySocket::SendHTTPQuery(LPCSTR lpHTTPQuery, INT dwTotalBytesSend)
{
	if(m_ProxyData.GetType() == PROXYTYPE_HTTP11QUERY)
	{
		LPSTR lpProxyHTTPQuery = new CHAR[dwTotalBytesSend + strlen(m_ProxyData.GetProxyHost()) + 20];
		ZeroMemory(lpProxyHTTPQuery, dwTotalBytesSend + strlen(m_ProxyData.GetProxyHost()) + 20);
		
		for(int i=0; i<dwTotalBytesSend; i++)
		{
			if(lpHTTPQuery[i] == ' ')
			{
				// XXX http://host:port/xxxx HTTP/xx 로 만들어준다
				CHAR temp[10]; ZeroMemory(temp, 10);
				strncat(temp, lpHTTPQuery, i);
				sprintf(lpProxyHTTPQuery, "%s http://%s:%d/", temp, m_ProxyData.GetDestinationHost(), m_ProxyData.GetDestinationPort());

				if(lpHTTPQuery[i+1] == '.') i++;
				if(lpHTTPQuery[i+1] == '/') i++;

				strcat(lpProxyHTTPQuery, lpHTTPQuery+i+1);
				
				if(!SendExact(lpProxyHTTPQuery, strlen(lpProxyHTTPQuery)))
				{
					delete [] lpProxyHTTPQuery;
					return false;
				}

				break;
			}
		}

		delete [] lpProxyHTTPQuery;
	}
	else
	{
		if(!SendExact(lpHTTPQuery, dwTotalBytesSend)) return FALSE;
	}

	return true;
}


bool ProxySocket::WinInetConnect(char *strRetVal, int nRetValSize, char *strAgent, char *strServerAddr, int nServerPort, char *strUrl)
{
	Socket::PrintLog(1 , "ProxySocket::WinInetConnect(strAgent:%s strServerAddr:%s nPort:%d strUrl:%s) Start\r\n", strAgent, strServerAddr, nServerPort, strUrl);
	Socket::PrintLog(1 , "Proxy Information(IP:%s, Port:%d, ID:%s, PW:%s\r\n", m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort(), m_ProxyData.GetUser(), m_ProxyData.GetPass());
	WinINetDownLoader winInet;
	DWORD dwStatus;
	DWORD dwStatusSize = sizeof(dwStatus);
	DWORD dwRetValSize = nRetValSize;
	
	//winInet.InternetOpen(strAgent, INTERNET_OPEN_TYPE_PROXY, m_ProxyData.GetProxyHost());
	winInet.InternetOpen(strAgent, INTERNET_OPEN_TYPE_PRECONFIG);
	winInet.InternetConnect(strServerAddr, nServerPort);
	winInet.HttpOpenRequest(strUrl);

	winInet.HttpSendRequest();
	winInet.HttpQueryInfo(HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);

	if(dwStatus == 200)
	{
		winInet.InternetReadFile(strRetVal, dwRetValSize, &dwRetValSize);
		Socket::PrintLog(1 , "ProxySocket::WinInetConnect() 200 OK, retVal:%s\r\n", strRetVal);
		return true;	
	}
	else
	{
		Socket::PrintLog(1 , "ProxySocket::WinInetConnect() failed. Try with proxy basic authentification. error code:%d\r\n", dwStatus);
	}

	if(dwStatus == HTTP_STATUS_PROXY_AUTH_REQ)
	{
		winInet.InternetSetOption(INTERNET_OPTION_PROXY_USERNAME, 
							  m_ProxyData.GetUser(), 
							  strlen(m_ProxyData.GetUser())+1);

		winInet.InternetSetOption(INTERNET_OPTION_PROXY_PASSWORD, 
							  m_ProxyData.GetPass(), 
							  strlen(m_ProxyData.GetPass())+1);
	}
	else if(dwStatus == HTTP_STATUS_DENIED)
	{
		winInet.InternetSetOption(INTERNET_OPTION_USERNAME, 
							  m_ProxyData.GetUser(), 
							  strlen(m_ProxyData.GetUser())+1);

		winInet.InternetSetOption(INTERNET_OPTION_PASSWORD, 
							  m_ProxyData.GetPass(), 
							  strlen(m_ProxyData.GetPass())+1);
	}

	winInet.HttpSendRequest();
	winInet.HttpQueryInfo(HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);

	if(dwStatus == 200)
	{
		winInet.InternetReadFile(strRetVal, dwRetValSize, &dwRetValSize);
		Socket::PrintLog(1 , "ProxySocket::WinInetConnect() 200 OK, retVal:%s\r\n", strRetVal);
		return true;	
	}
	
	Socket::PrintLog(1 , "ProxySocket::WinInetConnect() failed. Try with NTML proxy authentification. error code:%d\r\n", dwStatus);
	winInet.InternetCloseHandle();
	
	char proxyInfo[50]; ZeroMemory(proxyInfo, sizeof(proxyInfo));
	sprintf(proxyInfo, "%s:%d", m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort());
	winInet.InternetOpen(strAgent, INTERNET_OPEN_TYPE_PROXY, proxyInfo);
	winInet.InternetConnect(strServerAddr, nServerPort);
	winInet.HttpOpenRequest(strUrl);

	winInet.InternetSetOption(INTERNET_OPTION_PROXY_USERNAME, 
							  m_ProxyData.GetUser(), 
							  strlen(m_ProxyData.GetUser())+1);

	winInet.InternetSetOption(INTERNET_OPTION_PROXY_PASSWORD, 
							  m_ProxyData.GetPass(), 
							  strlen(m_ProxyData.GetPass())+1);

	winInet.HttpSendRequest();
	winInet.HttpQueryInfo(HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);
		
	if(dwStatus == 200)
	{
		winInet.InternetReadFile(strRetVal, dwRetValSize, &dwRetValSize);
		Socket::PrintLog(1 , "ProxySocket::WinInetConnect() 200 OK, retVal:%s\r\n", strRetVal);
		return true;	
	}

	return false;	
}




