// blastsock.cpp: implementation of the blastsock class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "blastsock.h"
#include "neturoPassword.h"
#include <tlhelp32.h>

// -- for registry ------------------------------
#include <atlbase.h> 


// For WinInet.h, WinHttp.h include together.
#include "WinINetDownLoader.h"


#include "base64.h"
#include "NTLM.h"
#include "AllNTLM.h"
#include "md4.h"
#include "md5c.h"
#include "smbencrypt.h"

#include "shlobj.h"
#include "strsafe.h"



#undef BOOLAPI
#undef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#undef SECURITY_FLAG_IGNORE_CERT_CN_INVALID

#define URL_COMPONENTS URL_COMPONENTS_ANOTHER
#define URL_COMPONENTSA URL_COMPONENTSA_ANOTHER
#define URL_COMPONENTSW URL_COMPONENTSW_ANOTHER

#define LPURL_COMPONENTS LPURL_COMPONENTS_ANOTHER
#define LPURL_COMPONENTSA LPURL_COMPONENTS_ANOTHER
#define LPURL_COMPONENTSW LPURL_COMPONENTS_ANOTHER

#define INTERNET_SCHEME INTERNET_SCHEME_ANOTHER
#define LPINTERNET_SCHEME LPINTERNET_SCHEME_ANOTHER

#define HTTP_VERSION_INFO HTTP_VERSION_INFO_ANOTHER
#define LPHTTP_VERSION_INFO LPHTTP_VERSION_INFO_ANOTHER

#include <winhttp.h>

#undef URL_COMPONENTS
#undef URL_COMPONENTSA
#undef URL_COMPONENTSW

#undef LPURL_COMPONENTS
#undef LPURL_COMPONENTSA
#undef LPURL_COMPONENTSW

#undef INTERNET_SCHEME
#undef LPINTERNET_SCHEME

#undef HTTP_VERSION_INFO
#undef LPHTTP_VERSION_INFO





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





// 2008.06.20 - by min blastsock 최적화
//const int blastsock::CRYPTBUFFERSIZE = 2048;
const int blastsock::CRYPTBUFFERSIZE = 8192;


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

bool blastsock::StartLog(LPTSTR filename  , bool bEncrypt)
{
	if(filename == NULL)
		return false;
//	if(!kLog)
//		kLog = new BlastLog(); 
	return Socket::StartLog(filename , bEncrypt);
}

blastsock::blastsock() : Socket()
{
	// Proxy Tunneling Variable
	m_tunnelingmode = BLASTSOCK_NO_PROXYTUNNELING;
//	m_pProxyinfo = NULL;
	m_proxyinfoown = false;
	//m_pProxydata = NULL;
	m_proxydataLen = 0;
	
	// AES Crypt Variable
	m_cryptmode = BLASTSOCK_NO_CRYPT;
	m_pCryptlib = NULL;
	m_cryptown = false;
	m_pCryptqueue = NULL;
	m_lpSendCryptBuf = m_lpRecvCryptBuf = m_lpRecvCryptBuf2 = NULL;

	//m_pSelectedProxyData = NULL;

	//m_pSelectedProxyData = NULL;
	//m_pSelectedProxyData = new CProxyData();
	m_bUseProxy = FALSE;
	ZeroMemory(&m_szProxyIP, sizeof(m_szProxyIP)); 
	ZeroMemory(&m_szProxyID, sizeof(m_szProxyID));
	ZeroMemory(&m_szProxyPW, sizeof(m_szProxyPW));

	m_nProxyPort = 0;

//	StartLog(_T("blast.log") , false);
}

blastsock::blastsock(blastsock* s) : Socket()
{	// 일단은 암호화 정보만 넘기는 역할
	// 프록시 정보는 그냥 초기화 (귀찮어.ㅡ.ㅡ:)
	m_tunnelingmode = BLASTSOCK_NO_PROXYTUNNELING;
//	m_pProxyinfo = NULL;
	m_proxyinfoown = false;
	//m_pProxydata = NULL;
	m_proxydataLen = 0;

	m_cryptmode = s->m_cryptmode;
	m_pCryptqueue = NULL;
	if(s->m_pCryptlib)
	{
		if(s->m_cryptown)
		{
			m_pCryptlib = new neturoCrypto;
			m_pCryptlib->SetAESiv(s->m_pCryptlib->GetHexEncodediv());
			m_pCryptlib->SetAESKey(s->m_pCryptlib->GetHexEncodedKey());
			m_cryptown = true;
		}
		else
		{
			m_pCryptlib = s->m_pCryptlib;
			m_cryptown = false;
		}
	}
	else
	{
		m_pCryptlib = NULL;
		m_cryptown = false;
	}
	m_lpSendCryptBuf = m_lpRecvCryptBuf = m_lpRecvCryptBuf2 = NULL;

	if(s->m_lpSendCryptBuf != NULL) m_lpSendCryptBuf = new CHAR[blastsock::CRYPTBUFFERSIZE];
	if(s->m_lpRecvCryptBuf != NULL) m_lpRecvCryptBuf = new CHAR[blastsock::CRYPTBUFFERSIZE];
	if(s->m_lpRecvCryptBuf2 != NULL) m_lpRecvCryptBuf2 = new CHAR[blastsock::CRYPTBUFFERSIZE];

	//m_pSelectedProxyData = NULL;
	m_bManualProxy = FALSE;
	m_bUseProxy = FALSE;
	ZeroMemory(&m_szProxyIP, sizeof(m_szProxyIP));
	ZeroMemory(&m_szProxyID, sizeof(m_szProxyID));
	ZeroMemory(&m_szProxyPW, sizeof(m_szProxyPW));

	m_nProxyPort = 0;

	if(!kLog)
		kLog = new BlastLog(); 
}

blastsock::~blastsock()
{
	// Proxy Tunneling Variable
//	if(m_pProxyinfo && m_proxyinfoown) delete m_pProxyinfo;
//	if(m_pProxydata) delete [] m_pProxydata;
	
	// AES Crypt Variable
	if(m_pCryptlib && m_cryptown) delete m_pCryptlib;
	if(m_pCryptqueue) delete m_pCryptqueue;
	if(m_lpSendCryptBuf) delete [] m_lpSendCryptBuf;
	if(m_lpRecvCryptBuf) delete [] m_lpRecvCryptBuf;
	if(m_lpRecvCryptBuf2) delete [] m_lpRecvCryptBuf2;

//	if(m_pSelectedProxyData)
//	{
//		delete m_pSelectedProxyData;
//		m_pSelectedProxyData = NULL;
//	}

	if(kLog)
		delete kLog;
}

bool blastsock::WinInetConnect(char *strRetVal, int nRetValSize, char *strAgent, char *strServerAddr, int nServerPort, char *strUrl, HKEY hKeyParent, LPCSTR lpszKeyName)
{
	Socket::PrintLog(1 , "blastsock::WinInetConnect(strAgent:%s strServerAddr:%s nPort:%d strUrl:%s lpszKeyName:%s) Start\r\n", strAgent, strServerAddr, nServerPort, strUrl, lpszKeyName);
	WinINetDownLoader winInet;
	DWORD dwStatus;
	DWORD dwStatusSize = sizeof(dwStatus);
	DWORD dwRetValSize = nRetValSize;
	
	winInet.InternetOpen(strAgent);
	winInet.InternetConnect(strServerAddr, nServerPort);
	winInet.HttpOpenRequest(strUrl);
	winInet.HttpSendRequest();
	winInet.HttpQueryInfo(HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);
	
	if(dwStatus != 200)
	{
		Socket::PrintLog(1 , "blastsock::WinInetConnect() failed. Try ProxySocket::WinInetConnect(). error code:%d\r\n", dwStatus);
		CheckProxyEnvironment(hKeyParent, lpszKeyName);
		//return ProxySocket::WinInetConnect(strRetVal, nRetValSize, strAgent, strServerAddr, nServerPort, strUrl);
		return false;
	}
	else // 200 OK
	{
		winInet.InternetReadFile(strRetVal, dwRetValSize, &dwRetValSize);
		Socket::PrintLog(1 , "blastsock::WinInetConnect() 200 OK, retVal:%s\r\n", strRetVal);
	}
	
	return true;
}

bool blastsock::IsProxyEnv()
{
//	if(!m_pProxyinfo) return false;
//	if(m_pProxyinfo->GetProxyEnv() == PROXYENV_DIRECT || m_pProxyinfo->GetProxyEnv() == PROXYENV_UNKNOWN) return false;
	return true;
}

bool blastsock::CryptInit(int crypt, neturoCrypto* cryptlib, RSAKey* rsakey)
{
	m_cryptmode = crypt;

	if(m_cryptmode == BLASTSOCK_CRYPT_CREATEAESKEY ||
	   m_cryptmode == BLASTSOCK_CRYPT_RECVAESKEY ||
	   m_cryptmode == BLASTSOCK_CRYPT)
   {
		if(!m_pCryptlib && cryptlib == NULL) 
		{
			m_pCryptlib = new neturoCrypto;
			m_cryptown = true;
		}

		if(cryptlib) 
		{
			if(m_cryptown) delete m_pCryptlib;
			m_pCryptlib = cryptlib;
			m_cryptown = false;
		}

		// 버퍼초기화
		if(m_lpSendCryptBuf == NULL) m_lpSendCryptBuf = new CHAR[blastsock::CRYPTBUFFERSIZE];
		if(m_lpRecvCryptBuf == NULL) m_lpRecvCryptBuf = new CHAR[blastsock::CRYPTBUFFERSIZE];
		if(m_lpRecvCryptBuf2 == NULL) m_lpRecvCryptBuf2 = new CHAR[blastsock::CRYPTBUFFERSIZE];
   }

	// 암호화프로토콜
	switch(m_cryptmode)
	{
	case BLASTSOCK_CRYPT_CREATEAESKEY: 
	// 암호화키를 받아서 생성한 AES 키를 암호화하여 보낸다.
		Socket::PrintLog(0 , "CryptInit(BLASTSOCK_CRYPT_CREATEAESKEY)\r\n");
		return CryptCreateAESKey();
		break;
	case BLASTSOCK_CRYPT_RECVAESKEY: 
	// 받은 AES 키를 복호화키로 복호화하여 저장한다.
		Socket::PrintLog(0 , "CryptInit(BLASTSOCK_CRYPT_RECVAESKEY)\r\n");
		return CryptRecvAESKey(rsakey);
		break;
	case BLASTSOCK_CRYPT: 
	// 이미 AES 키를 가지고 있다. (AES 키를 가지고 있지 않은 경우 책임못짐-_-)
		Socket::PrintLog(0 , "CryptInit(BLASTSOCK_CRYPT)\r\n");
		return true;
		break;
	case BLASTSOCK_NO_CRYPT: 
	// 암호화 안한다. 할말없음.ㅋ
		Socket::PrintLog(0 , "CryptInit(BLASTSOCK_NO_CRYPT)\r\n");
		return true;
		break;
	default:
	// 파라미터 에러
		Socket::PrintLog(0 , "[Error]CryptInit(BLASTSOCK_ERROR_PARAMETER)\r\n");
		Socket::SetLastError(BLASTSOCK_ERROR_PARAMETER);
		return false;
	}
}

bool blastsock::CryptCreateAESKey()
{
	Socket::PrintLog(1 , "blastsock::CryptCreateAESKey() start\r\n");
	char rsa_public_key[321];
	char aes_secret_key[257];
	ZeroMemory(&rsa_public_key, sizeof(rsa_public_key));
	ZeroMemory(&aes_secret_key, sizeof(aes_secret_key));
	
	if(!Socket::RecvExact((char*)&rsa_public_key, sizeof(rsa_public_key)))
	{
		Socket::PrintLog(2 , "[Error] Fail to RecvExact(rsa_publick_key)\r\n");
		return false;
	}
	
	Socket::PrintLog(2 , "RecvExact(rsa_publick_key : %s)\r\n" , rsa_public_key);

	m_pCryptlib->InitAESKey();
				
	// Encrypt AES128 Key by RSA Public Key
	byte KeyandIV[(AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) * 2+1];
	ZeroMemory(KeyandIV, (AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) * 2+1);
	memcpy(KeyandIV, m_pCryptlib->GetHexEncodedKey(), AES::DEFAULT_KEYLENGTH * 2);
	memcpy(KeyandIV + AES::DEFAULT_KEYLENGTH*2, m_pCryptlib->GetHexEncodediv(), AES::BLOCKSIZE*2);
	string EncryptedAESKey = m_pCryptlib->RSAEncryptString(rsa_public_key, (const char *)KeyandIV);
	if(EncryptedAESKey.length() == 0) return false;
	memcpy(aes_secret_key, EncryptedAESKey.c_str(), 256);

	if(!Socket::SendExact((char*)&aes_secret_key, sizeof(aes_secret_key))) 
	{
		Socket::PrintLog(2 , "[Error] Fail to SendExact(aes_secret_key)\r\n");
		return false;
	}

	Socket::PrintLog(2 , "SendExact(aes_secret_key : %s)\r\n" , aes_secret_key);
	Socket::PrintLog(1 , "blastsock::CryptCreateAESKey() End\r\n");
	
	return true;
}

bool blastsock::CryptRecvAESKey(RSAKey* rsakey)
{
	Socket::PrintLog(1 , "blastsock::CryptRecvAESKey() Start\r\n");
	char pvk[1300];
	char pbk[321];
	char rsa_public_key[321];
	char aes_secret_key[257];

	ZeroMemory(pvk, sizeof(pvk));
	ZeroMemory(pbk, sizeof(pbk));
	ZeroMemory(&rsa_public_key, sizeof(rsa_public_key));
	ZeroMemory(&aes_secret_key, sizeof(aes_secret_key));
	
	// Initialize RSA Private & Public Key - by scyrie
	if(rsakey) 
	{	// RSA 키가 있으면 그걸로 대체하고
		memcpy(pvk, rsakey->pvk, 1300);
		memcpy(pbk, rsakey->pbk, 321);
	}
	else
	{	// 없으면 새로 만들어서 쓴다
		m_pCryptlib->GenerateRSAKey(1024, pvk, pbk);
	}
	
	// Key Exchange by scyrie
	memcpy(rsa_public_key, pbk, 320);
	if(!Socket::SendExact((LPSTR)&rsa_public_key, sizeof(rsa_public_key))) 
	{
		Socket::PrintLog(2 , "[Error] Fail to SendExact(rsa_public_key)\r\n");
		return false;
	}

	Socket::PrintLog(2 , "SendExact(rsa_public_key : %s)\r\n" , rsa_public_key);

	if(!Socket::RecvExact((LPSTR)&aes_secret_key, sizeof(aes_secret_key)))
	{
		Socket::PrintLog(2 , "[Error] Fail to RecvExact(aes_secret_key)\r\n");
		return false;
	}

	Socket::PrintLog(2 , "RecvExact(aes_secret_key : %s)\r\n" , aes_secret_key);
	
	// Decrypt Key & IV and Seperate them.
	byte KeyandIV[(AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) *2 +1];
	ZeroMemory(KeyandIV, (AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) *2 +1);

	memcpy(KeyandIV, (m_pCryptlib->RSADecryptString(pvk, aes_secret_key)).c_str(), (AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) * 2 + 1);
	
	m_pCryptlib->SetAESKey(KeyandIV);
	m_pCryptlib->SetAESiv(KeyandIV + AES::DEFAULT_KEYLENGTH*2);
	
	Socket::PrintLog(1 , "blastsock::CryptRecvAESKey() End\r\n" );
	return TRUE;
}

BOOL blastsock::GetLogPath(TCHAR * savePath)
{
	TCHAR szDocumentPath[MAX_PATH] = _T("");


	if (IsWinXPorLater())
	{
		PWSTR path = NULL;

		// Vista 이상의 버전일 경우 SHGetKnownFolderPath로 얻어온다
		//GUID FOLDERID_PublicDocuments = {0xFDD39AD0, 0x238F, 0x46AF, {0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7}}; //내문서
		GUID FOLDERID_PublicDocuments = { 0xED4824AF, 0xDCE4, 0x45A8,{ 0x81, 0xE2, 0xFC, 0x79, 0x65, 0x08, 0x36, 0x34 } }; //공용문서

		typedef UINT(CALLBACK* LPFNDLLFUNC)(GUID& rfid, DWORD dwFlags, HANDLE hToken, PWSTR *ppszPath);
		HINSTANCE hShell = LoadLibrary(_T("shell32.dll"));
		LPFNDLLFUNC pGetKnownFldPathFnPtr = (LPFNDLLFUNC)GetProcAddress(hShell, "SHGetKnownFolderPath");

		if (pGetKnownFldPathFnPtr)
		{
			size_t len;
			if (SUCCEEDED(pGetKnownFldPathFnPtr(FOLDERID_PublicDocuments, 0, NULL, &path)))
			{
				HRESULT hr = StringCchLengthW(path, STRSAFE_MAX_CCH, &len);
				if (SUCCEEDED(hr))
				{
					WideCharToMultiByte(CP_ACP, 0, path, len, szDocumentPath, MAX_PATH, NULL, NULL);
				}
				CoTaskMemFree(path);
			}
			FreeLibrary(hShell);
		}
	}
	else
	{
		// Vista 미만의 버전일 경우 SHGetSpecialFolderPath로 얻어온다
		::SHGetSpecialFolderPath(NULL, szDocumentPath, CSIDL_COMMON_DOCUMENTS, TRUE);
		//savePath.Format(_T("%s"), path);
	}

	_tcscat(szDocumentPath, "\\");
	_tcscpy(savePath, szDocumentPath);

#ifdef LMMSE_SERVICE
	_tcscat(savePath, _T("LinkMeMineSE\\"));
#else
	_tcscat(savePath, _T("LinkMeMine\\"));
#endif

	_tcscat(savePath, _T("log\\"));
	_tcscat(savePath, _T("FileTransfer\\"));

	return TRUE;
}


//bool blastsock::TunnelingInit(unsigned int tunneling, CProxyInfo* pProxyInfo, bool fromIE, bool regsave, bool cfileown, HKEY hKeyParent, LPCSTR lpszKeyName)
bool blastsock::TunnelingInit(unsigned int tunneling, void* pProxyInfo, bool fromIE, bool regsave, bool cfileown, HKEY hKeyParent, LPCSTR lpszKeyName)
{
	char buffer[256] = { 0, };
	char szLogPath[256] = {0, };
	GetLogPath(szLogPath);

	sprintf(buffer, "%sblastSock_%s.log", szLogPath, lpszKeyName);

	StartLog(buffer, false);



	Socket::PrintLog(1 , "blastsock::TunnelingInit(tunneling(%d) , fromIE(%d) , regsave(%d) , cfileown(%d) , lpszKeyName(%s) start\r\n",
		tunneling , fromIE , regsave , cfileown , lpszKeyName);

	m_tunnelingmode = tunneling;
	if(m_tunnelingmode == BLASTSOCK_PROXYTUNNELING || m_tunnelingmode == BLASTSOCK_PROXYQUERY)
	{
		CheckProxyEnvironment(hKeyParent, lpszKeyName);
	}
	Socket::PrintLog(1 , "blastsock::TunnelingInit(m_tunnelingmode = %d) End\r\n" , m_tunnelingmode);
	return true;
}

void blastsock::CheckProxyEnvironment(HKEY hKeyParent, LPCSTR lpszKeyName)
{
	/*
	if(IsWinXPorLater()) 
	{
		HANDLE hToken = GetToken();
		BOOL ret = ImpersonateLoggedOnUser(hToken);
	}	
	*/
	/*
	proxy 설정이 되어 있으면
	1) serverconfig에서 proxy IP, Port 정보를 가져오고
	2) IP(_T("") , PORT(0) 이면 , IE에서 정보를 다시 한번 검색한다.

	proxy 사용안함으로 되어 있다면 , IE에서 정보를 검색한다.
	*/


	bool bUseProxy = CheckManualProxy(hKeyParent, lpszKeyName);

	if (!bUseProxy)
	{
		FindProxyFromWinHttp();
	}

//	m_ProxyData = *m_pSelectedProxyData;

	/*
	if(IsWinXPorLater()) 
	{
		RevertToSelf();
	}
	*/
}

bool blastsock::CheckManualProxy(HKEY hKeyParent, LPCSTR lpszKeyName)
{
	Socket::PrintLog(2 , "Start CProxyInfo::CheckManualProxy(lpszKeyName : %s)\r\n" , lpszKeyName);

	char moduleFilenameBuf[MAX_PATH] = { 0, };

	int res = GetModuleFileName(NULL, moduleFilenameBuf, MAX_PATH);
	while (res > 0)
	{
		if (moduleFilenameBuf[--res] == '\\')
		{
			moduleFilenameBuf[res] = '\0';
			break;
		}
	}
	
	char szBuf[64] = { 0, };
	char szConfigPath[MAX_PATH] = { 0, };
	sprintf(szConfigPath, "%s\\config.ini", moduleFilenameBuf);
	

	GetPrivateProfileString(_T("AGENT"), _T("UsingProxyServer"), _T("0"), szBuf, 64, szConfigPath);
	m_bUseProxy = _ttoi(szBuf);
	Socket::PrintLog(2, "UsingProxyServer (%d)\r\n", m_bUseProxy);

	if (m_bUseProxy)
	{
		GetPrivateProfileString(_T("AGENT"), _T("ProxyServerIP"), _T(""), szBuf, 64, szConfigPath);
		strcpy(m_szProxyIP, szBuf);

		GetPrivateProfileString(_T("AGENT"), _T("ProxyServerPort"), _T("0"), szBuf, 64, szConfigPath);
		m_nProxyPort = _ttoi(szBuf);

		GetPrivateProfileString(_T("AGENT"), _T("ProxyServerID"), _T(""), szBuf, 64, szConfigPath);
		strcpy(m_szProxyID, szBuf);

		GetPrivateProfileString(_T("AGENT"), _T("ProxyServerPW"), _T(""), szBuf, 64, szConfigPath);
		strcpy(m_szProxyPW, szBuf);

		if (strcmp(m_szProxyIP, "") == 0 || m_nProxyPort == 0)
		{
			m_bUseProxy = (int)false;
		}
	}

	

	Socket::PrintLog(2 , "m_pSelectedProxyData->SetType(PROXYTYPE_HTTP11)\r\n");
	Socket::PrintLog(2 , "End CProxyInfo::CheckManualProxy(%d , %s , %d , %s , %s)\r\n" ,
		m_bUseProxy, m_szProxyIP, m_nProxyPort,
		m_szProxyID, m_szProxyPW);

	return m_bUseProxy;
}

bool blastsock::Connect(char *addr, unsigned int port)
{
	Socket::PrintLog(1 , "blastsock::Connect(%s : %d) Start\r\n" , addr , port);

	int i;

	switch(m_tunnelingmode)
	{
	case BLASTSOCK_PROXYTUNNELING_MANUAL:
	case BLASTSOCK_PROXYQUERY: 
	case BLASTSOCK_PROXYTUNNELING: 
		Socket::PrintLog(2 , "m_tunnelingmode == BLASTSOCK_PROXYQUERY ||  BLASTSOCK_PROXYTUNNELING (%d)\r\n" , m_tunnelingmode);
		/* destination port 가 443 이라면 proxy 환경이더라도 
		   direct 로 열어 놓았을 가능성이 높으므로 일단 바로 접속을 해본다 */
		//if(m_pProxyinfo->GetProxyEnv() == PROXYENV_UNKNOWN || m_pProxyinfo->GetProxyEnv() == PROXYENV_DIRECT)
		//if(port == 443 || port == 80) 
		//port scanning으로 서버외에는 P2P 연결 시 80 , 443을 사용하지 않는다.
		//항상 direct로 연결을 시도 해 본다.


		if(!m_bUseProxy)
		{
			Socket::PrintLog(2 , "Try to connect directly(%s : %d)\r\n" , addr , port);

			//if(Socket::Connect(addr, port)) 
			if(Socket::Connect(addr, port , false )) 
			{
				Socket::PrintLog(2 , "Success connect to destination directly(%s : %d)\r\n" , addr , port);
				Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
			
				return true;
			}
			else
			{
				Socket::PrintLog(2 , "Fail to connect direct(%s : %d), GetLastError:%d\r\n" , addr , port, Socket::GetLastError());
				return false;
			}
		}
		else //
		{

			bool result = ConnecToProxyTunnel(addr, port);
			if (result)
				return true;
			else
				return Socket::Connect(addr, port, false);
			
		}
		break;
	case BLASTSOCK_NO_PROXYTUNNELING: 
		Socket::PrintLog(2 , "m_tunnelingmode == BLASTSOCK_NO_PROXYTUNNELING \r\n");
		//if(!Socket::Connect(addr, port))
		if(!Socket::Connect(addr, port , false /* non-blocking */))
		{
			Socket::PrintLog(2 , "[Fail] Socket::Connect(%s , %d)\r\n" , addr , port);
			Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
		
			return false;
		}
		Socket::PrintLog(2 , "Success Socket::Connect(%s , %d)\r\n" , addr , port);
		break;
	default: 
		Socket::PrintLog(2 , "[Error] BLASTSOCK_ERROR_PARAMETER \r\n");
		Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
	
		Socket::SetLastError(BLASTSOCK_ERROR_PARAMETER);
		
		return false;
	}

	Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
	return true;
}

bool blastsock::ConnecToProxyTunnel(char* host, int port)
{
	Socket::PrintLog(2, "blastsock::ConnecToProxyTunnel(%s , %d)  START \r\n", host, port);


	//1)HTTP로 접속 해본다.
	bool result = false;
	result = ConnectHTTP11(host, port);

	if (result == false)
	{
		//2)SOCKS4
		result = ConnectSOCKS4(host, port);
	}
	else
	{
		return result; //HTTP11 성공
	}

	if (result) //SOCKS4 성공시 
		return result;

	//3)SOCKS5로 시도
	result = ConnectSOCKS5(host, port);
	
	return result;

}


bool blastsock::ConnectHTTP11(char *host, unsigned short port)
{
	int result;

	//proxy server에 접속
	Socket::PrintLog(0 , "[SOCKET]Try ConnectHTTP11 REAL IP(%s , %d)\r\n" , host, port);
	Socket::PrintLog(0 , "[SOCKET]Try ConnectHTTP11 PROXY (%s , %d)\r\n" , m_szProxyIP,m_nProxyPort);


	bool bResult = false;
	
	Socket::PrintLog(0, "Try Connect to proxyServer(%s , %d)  START \r\n", m_szProxyIP, m_nProxyPort);
	bResult = Socket::Connect(m_szProxyIP, m_nProxyPort, false);
	if(bResult  == false) 
	{
		Socket::PrintLog(0, "[Fail] blastsock::ConnecToProxyTunnet(%s , %d)\r\n", host, port);
		Socket::PrintLog(0, "blastsock::ConnectHTTP11 END\r\n");
		return false;
	}

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

	result = Socket::Send(buffer, strlen(buffer));

	if (result <= 0)
	{
		Socket::PrintLog(2, "[SOCKET]ConnectHTTP11 , Send Error 1\r\n");
		return false;
	}

	Socket::PrintLog(2, "[SOCKET]ConnectHTTP11==> : %s\r\n", buffer);

	ZeroMemory(buffer, sizeof(buffer));
	
	result = Socket::Recv(buffer, sizeof(buffer));
	
	if (result <= 0)
	{
		Socket::PrintLog(2, "[SOCKET]ConnectHTTP11 , Recv Error 1\r\n");
		return false;
	}

	Socket::PrintLog(2, "[SOCKET]ConnectHTTP11<== : %s\r\n" , buffer);


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
		Socket::PrintLog(2, "[SOCKET]Success ConnectHTTP11 200OK\r\n");
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

			bResult = FALSE;

			bResult = Socket::Connect(m_szProxyIP, m_nProxyPort, false);
			if ( bResult == false)
			{
				Socket::PrintLog(2, "[Fail] blastsock::ConnecToProxyTunnet(%s , %d)\r\n", m_szProxyIP, m_nProxyPort);
				Socket::PrintLog(1, "blastsock::ConnectHTTP11 END\r\n");
				return false;
			}
		
			// Basic auth info
			char user_pass[512];
			char encoded[512];

			int wlen = _snprintf(user_pass, 512, "%s:%s",m_szProxyID, m_szProxyPW);
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

			bResult = FALSE;
			bResult = Socket::Connect(m_szProxyIP, m_nProxyPort, false);

			if (bResult  == false)
			{
				Socket::PrintLog(2, "[Fail] blastsock::ConnecToProxyTunnet(%s , %d)\r\n", m_szProxyIP, m_nProxyPort);
				Socket::PrintLog(1, "blastsock::ConnectHTTP11 END\r\n");
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
				host, port, host, port, m_szProxyID, m_szrealm, m_sznonce, host, port, m_szcnonce, m_nonceCount, m_szresponse, m_szqop, m_szopaque);

		}
		else if (strcmp(szAuthCode, "NTLM") == 0 || strcmp(szAuthCode, "Ntlm") == 0 || strcmp(szAuthCode, "ntlm") == 0)
		{

			CloseSocket();
			Create();

			bResult = FALSE;
			bResult = Socket::Connect(m_szProxyIP, m_nProxyPort, false);

			if (bResult  == false)
			{
				Socket::PrintLog(2, "[Fail] blastsock::ConnecToProxyTunnet(%s , %d)\r\n", m_szProxyIP, m_nProxyPort);
				Socket::PrintLog(1, "blastsock::ConnectHTTP11 END\r\n");
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

			strcpy(account, m_szProxyID);

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
			strcpy(ntlm_userpw, m_szProxyPW);

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



			result = Socket::Send(buffer, strlen(buffer));

			if (result <= 0)
			{
				Socket::PrintLog(2, "[SOCKET]ConnectHTTP11 , Send Error 2\r\n");
				return false;
			}

			Socket::PrintLog(2, "[SOCKET]ConnectHTTP11==> : %s\r\n", buffer);

			ZeroMemory(buffer, sizeof(buffer));

			result = Socket::Recv(buffer, sizeof(buffer));

			if (result <= 0)
			{
				Socket::PrintLog(2, "[SOCKET]ConnectHTTP11 , Recv Error 2\r\n");
				return false;
			}

			Socket::PrintLog(2, "[SOCKET]ConnectHTTP11<== : %s\r\n", buffer);


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

		result = Socket::Send(buffer, strlen(buffer));

		if (result <= 0)
		{
			Socket::PrintLog(2, "[SOCKET]ConnectHTTP11 , Send Error 3\r\n");
			return false;
		}

		Socket::PrintLog(2, "[SOCKET]ConnectHTTP11==> : %s\r\n", buffer);

		ZeroMemory(buffer, sizeof(buffer));

		result = Socket::Recv(buffer, sizeof(buffer));

		if (result <= 0)
		{
			Socket::PrintLog(2, "[SOCKET]ConnectHTTP11 , Recv Error 3\r\n");
			return false;
		}

		Socket::PrintLog(2, "[SOCKET]ConnectHTTP11<== : %s\r\n", buffer);

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
		memcpy(szAuthCode, p + 1, len);
		dwStatusCode = atoi(szAuthCode);

		if (dwStatusCode == 200)
		{
			return true;
		}
		else if (dwStatusCode == 401 || dwStatusCode == 407)
		{
			return false;
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}

	return true;
}

// 2008.06.20 - by min blastsock 최적화
// data 길이를 같이 보내 Socket IO를 최소화 한다.
bool blastsock::SendExact(const char* buf, unsigned int bufLen, unsigned int usebuf)
{
	// 암호화하지 않을 경우
	if(m_cryptmode == BLASTSOCK_NO_CRYPT) return Socket::SendExact(buf, bufLen);

	// 버퍼사용하는 경우 패킷의 길이를 먼저 보낸다
	if(usebuf == BLASTSOCK_BUFFER) 
	{	
		char * buff;
		buff = new char[bufLen+sizeof(unsigned int)+1];
		memcpy(buff, (char*)&bufLen, sizeof(unsigned int));
		
		if(bufLen <= blastsock::CRYPTBUFFERSIZE)
		{
			m_pCryptlib->AESEncryptString(m_lpSendCryptBuf, buf, bufLen);
			memcpy(buff+sizeof(unsigned int), m_lpSendCryptBuf, bufLen);

		}
		else
		{
			char* cryptbuf = new char[bufLen+1];
			m_pCryptlib->AESEncryptString(cryptbuf, buf, bufLen);
			memcpy(buff+sizeof(unsigned int), cryptbuf, bufLen);
			delete [] cryptbuf;
		}
	
		bool result =  Socket::SendExact(buff, bufLen+sizeof(unsigned int));
		
		delete [] buff;
		return result;

	}
	else{
		// 암호화해서 보낸다
		if(bufLen <= blastsock::CRYPTBUFFERSIZE)
		{
			m_pCryptlib->AESEncryptString(m_lpSendCryptBuf, buf, bufLen);
			return Socket::SendExact(m_lpSendCryptBuf, bufLen);
		}
		else
		{
			char* cryptbuf = new char[bufLen+1];
			m_pCryptlib->AESEncryptString(cryptbuf, buf, bufLen);
			bool result = Socket::SendExact(cryptbuf, bufLen);
			delete [] cryptbuf;
			return result;
		}
	}
}


bool blastsock::RecvExact(char* buf, unsigned int bufLen, unsigned int usebuf, int flags)
{
	// 암호화하지 않을 경우
	if(m_cryptmode == BLASTSOCK_NO_CRYPT) return Socket::RecvExact(buf, bufLen);

	// 버퍼사용X
	if(usebuf == BLASTSOCK_NO_BUFFER)
	{
		// 멤버 변수 버퍼 사용
		if(bufLen <= blastsock::CRYPTBUFFERSIZE)
		{
			if(!Socket::RecvExact(m_lpRecvCryptBuf, bufLen)) return false;
			m_pCryptlib->AESDecryptString(buf, m_lpRecvCryptBuf, bufLen);	
		}
		// 힙 공간에 버퍼 생성하여 사용
		else
		{
			char* cryptbuf = new char[bufLen+1];
			if(!Socket::RecvExact(cryptbuf, bufLen))
			{
				delete [] cryptbuf;
				return false;
			}
			m_pCryptlib->AESDecryptString(buf, cryptbuf, bufLen);	
			delete [] cryptbuf;
		}
		return true;
	}

	if(!m_pCryptqueue) m_pCryptqueue = new StringQueue();

	unsigned int iTotalBufferBytesRecv;
	while(bufLen > m_pCryptqueue->GetSize())
	{	// 받을 용량보다 버퍼의 내용이 적다면 더 받아서 버퍼에 저장한다
		if(!Socket::RecvExact((char*)&iTotalBufferBytesRecv, sizeof(unsigned int))) return false;

		// 멤버 변수 버퍼 사용
		if(iTotalBufferBytesRecv <= blastsock::CRYPTBUFFERSIZE)	
		{
			if(!Socket::RecvExact(m_lpRecvCryptBuf, iTotalBufferBytesRecv)) return false;
			m_pCryptlib->AESDecryptString(m_lpRecvCryptBuf2, m_lpRecvCryptBuf, iTotalBufferBytesRecv);	
			while(!m_pCryptqueue->Enqueue(m_lpRecvCryptBuf2, iTotalBufferBytesRecv))
			{
				// Buffer Overflow
				// 사이즈가 두배인 큐를 새로 생성한다
				StringQueue* _pCryptqueue = new StringQueue(m_pCryptqueue->GetMaxSize()*2);
				*_pCryptqueue = *m_pCryptqueue;
				delete m_pCryptqueue;
				m_pCryptqueue = _pCryptqueue;
			}
		}
		// 힙 공간에 버퍼 생성하여 사용
		else
		{
			char* cryptbuf = new char[iTotalBufferBytesRecv+1];
			if(!Socket::RecvExact(cryptbuf, iTotalBufferBytesRecv))
			{
				delete [] cryptbuf;
				return false;
			}
			char* cryptbuf2 = new char[iTotalBufferBytesRecv+1];
			m_pCryptlib->AESDecryptString(cryptbuf2, cryptbuf, iTotalBufferBytesRecv);	
			while(!m_pCryptqueue->Enqueue(cryptbuf2, iTotalBufferBytesRecv)) 
			{
				// Buffer Overflow
				// 사이즈가 두배인 큐를 새로 생성한다
				StringQueue* _pCryptqueue = new StringQueue(m_pCryptqueue->GetMaxSize()*2);
				*_pCryptqueue = *m_pCryptqueue;
				delete m_pCryptqueue;
				m_pCryptqueue = _pCryptqueue;
			}
			delete [] cryptbuf;
			delete [] cryptbuf2;
		}
	}
	
	if(!m_pCryptqueue->Dequeue(buf, bufLen, flags)) 
	{
		WSASetLastError(BLASTSOCK_ERROR_CRYPTBUFFEREMPTY);
		return false;
	}

	return true;
}

bool blastsock::FindProxyFromWinHttp()
{
	Socket::PrintLog(1 , "Start blastsock::FindProxyFromWinHttp\r\n");

	HINTERNET hHttpSession = NULL;
	HINTERNET hConnect     = NULL;
	HINTERNET hRequest     = NULL;
	
	WINHTTP_AUTOPROXY_OPTIONS  AutoProxyOptions;
	WINHTTP_PROXY_INFO         ProxyInfo;
	DWORD                      cbProxyInfoSize = sizeof(ProxyInfo);
	
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieProxyConfig = { 0 };
	ZeroMemory( &AutoProxyOptions, sizeof(AutoProxyOptions) );
	ZeroMemory( &ProxyInfo, sizeof(ProxyInfo) );
	
	char logbuf[512];
	memset(logbuf , 0x00 , sizeof(logbuf));
//	enum enumproxy {NO_PROXY , AUTO_CONFIG , MANUAL_CONFIG};

//	int bSuccess = 0;

	if (!::WinHttpGetIEProxyConfigForCurrentUser(&ieProxyConfig))
	{
		
		Socket::PrintLog(1 , "[FAIL] blastsock::FindProxyFromWinHttp / WinHttpGetIEProxyConfigForCurrentUser\r\n");
		goto NEXT;
	}
	
	wsprintf(logbuf , "ieProxyConfig ==>\r\n\t(AutoDetect : %d)\r\n\t(configUrl : %S)\r\n\t(szProxy : %S)\r\n\t(proxyBypass : %S)\r\n" , 
		ieProxyConfig.fAutoDetect , ieProxyConfig.lpszAutoConfigUrl , ieProxyConfig.lpszProxy , ieProxyConfig.lpszProxyBypass);
    Socket::PrintLog(1 , logbuf);

//	Socket::PrintLog(1 , "blastsock::FindProxyFromWinHttp / 1 \r\n");
	//PAC 방식이면

	if(ieProxyConfig.lpszAutoConfigUrl != NULL) //auto config
	{
		wsprintf(logbuf , "[SUCCESS] Get PAC file (%S) \r\n" , ieProxyConfig.lpszAutoConfigUrl);
		Socket::PrintLog(1 , logbuf);
	
		if(strlen((LPSTR)ieProxyConfig.lpszAutoConfigUrl))
		{
			AutoProxyOptions.lpszAutoConfigUrl = ieProxyConfig.lpszAutoConfigUrl;

			hHttpSession = WinHttpOpen( 0 ,
				WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
				WINHTTP_NO_PROXY_NAME,
				WINHTTP_NO_PROXY_BYPASS,
				WINHTTP_FLAG_ASYNC);
			
			// Exit if WinHttpOpen failed.
			if( !hHttpSession )
			{
				Socket::PrintLog(1 , "[FAIL] WinHttpOpen \r\n" );
				goto NEXT;
			}	
			
				// Use auto-detection because the Proxy 
			// Auto-Config URL is not known.
			AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
			
			// Use DHCP and DNS-based auto-detection.
			AutoProxyOptions.dwAutoDetectFlags = 
				WINHTTP_AUTO_DETECT_TYPE_DHCP |
				WINHTTP_AUTO_DETECT_TYPE_DNS_A;
			
			// If obtaining the PAC script requires NTLM/Negotiate
			// authentication, then automatically supply the client
			// domain credentials.
			AutoProxyOptions.fAutoLogonIfChallenged = TRUE;
			
			AutoProxyOptions.lpszAutoConfigUrl = ieProxyConfig.lpszAutoConfigUrl;
			
			if( WinHttpGetProxyForUrl( hHttpSession,
				L"http://www.anysupport.net",
				&AutoProxyOptions,
				&ProxyInfo))
			{
			
				if(ProxyInfo.lpszProxy == NULL)
				{
					goto NEXT;
				}

				if(strlen((LPSTR)ProxyInfo.lpszProxy) == 0 )
				{
					goto NEXT;
				}

				wsprintf(logbuf , "[SUCCESS] Get PAC Proxy Info (%S) \r\n" , ProxyInfo.lpszProxy);
				Socket::PrintLog(1 , logbuf);

				char buf[1024];
				memset(buf , 0x00 ,sizeof(buf));
				
				//strcpy(buf , (LPSTR)ProxyInfo.lpszProxy);
				wsprintf(buf , "%S" , ProxyInfo.lpszProxy);
				
				char*tok = NULL;
				
				if( (tok = strchr(buf, ';')) != NULL)
				{
					char temp[256];
					memset(temp , 0x00 , sizeof(temp));
					
					char temp1[256];
					memset(temp1 , 0x00 , sizeof(temp1));
					
					strncpy(temp , buf , strlen(buf)-strlen(tok));
					
					if((tok = strchr(temp , ':')) != NULL)
					{
						strncpy(temp1 , temp , strlen(temp)-strlen(tok));
						strcpy(m_szProxyIP , temp1);
						
						strcpy(temp , tok+1 );
						m_nProxyPort = (SHORT)atoi(temp);
						Socket::PrintLog(1 , "[SUCCESS] Get PAC Proxy IP:Port (%s:%d) \r\n" , m_szProxyIP, m_nProxyPort);
						goto END;
					}
					else
					{
						Socket::PrintLog(1 , "[FAIL] Get PAC Proxy IP:Port -1 \r\n");
						goto NEXT;
					}
				}
				else
				{
					if( (tok = strchr(buf, ':')) != NULL)
					{
						char temp[256];
						memset(temp , 0x00 , sizeof(temp));
						
						strncpy(temp , buf , strlen(buf)-strlen(tok));
						strcpy(m_szProxyIP, temp);
												
						memset(temp , 0x00 , sizeof(temp));
						strcpy(temp , tok+1 );

						m_nProxyPort = (SHORT)atoi(temp);
						Socket::PrintLog(1 , "[SUCCESS] Get PAC Proxy IP:Port (%s:%d) \r\n" , m_szProxyIP, m_nProxyPort);
						goto END;
					}
					else
					{
						Socket::PrintLog(1 , "[FAIL] Get PAC Proxy IP:Port -2 \r\n");
						goto NEXT;
					}
				}

			}
			else
			{
				Socket::PrintLog(1 , "[fail] Get PAC Proxy Info \r\n");
				goto NEXT;
			}
				
		}
	}

NEXT:

	if(ieProxyConfig.lpszProxy != NULL) //manual config
	{
		if(strlen((LPSTR)ieProxyConfig.lpszProxy)) //수동 방식이면
		{
			Socket::PrintLog(1 , "[SUCCESS] Get Manual Proxy Info from IE(%S) \r\n" , ieProxyConfig.lpszProxy);
			char buf[256];
			memset(buf , 0x00 ,sizeof(buf));
			wsprintf(buf , "%S" , ieProxyConfig.lpszProxy);
			char*tok = NULL;
			
			if( (tok = strchr(buf, ':')) != NULL)
			{
				char temp[256];
				memset(temp , 0x00 , sizeof(temp));
				
				strncpy(temp , buf , strlen(buf)-strlen(tok));
				strcpy(m_szProxyIP , temp);
								
				memset(temp , 0x00 , sizeof(temp));
				strcpy(temp , tok+1 );
				m_nProxyPort = (SHORT)atoi(temp) ;
				
				Socket::PrintLog(1 , "[SUCCESS] Get Manual IE Proxy IP:Port (%s:%d) \r\n" , m_szProxyIP, m_nProxyPort );
				goto END;
			}
			else
			{
				Socket::PrintLog(1 , "[fail] Get Manual IE Proxy IP:Port -1  \r\n");
				goto END;
			}
		}
		else //proxy 환경이 아님..
		{
			Socket::PrintLog(1 , "blastsock::FindProxyFromWinHttp / No Proxy Env \r\n");
			Socket::PrintLog(1 , "[fail] Get Manual IE Proxy IP:Port -2 \r\n");
			goto END;
		}
	}
	else
	{
		Socket::PrintLog(1 , "blastsock::FindProxyFromWinHttp / No Proxy Env \r\n");
	}

END :
	//
	// Clean up the WINHTTP_PROXY_INFO structure.
	//
	if( ieProxyConfig.lpszAutoConfigUrl != NULL )
		GlobalFree(ieProxyConfig.lpszAutoConfigUrl);

	if( ieProxyConfig.lpszProxyBypass != NULL )
		GlobalFree(ieProxyConfig.lpszProxyBypass);

	if( ieProxyConfig.lpszProxy != NULL )
		GlobalFree(ieProxyConfig.lpszProxy);


    if( ProxyInfo.lpszProxy != NULL )
		GlobalFree(ProxyInfo.lpszProxy);
	
    if( ProxyInfo.lpszProxyBypass != NULL )
		GlobalFree( ProxyInfo.lpszProxyBypass );
	
	//
	// Close the WinHTTP handles.
	//
    if( hRequest != NULL )
		WinHttpCloseHandle( hRequest );
	
    if( hConnect != NULL )
		WinHttpCloseHandle( hConnect );
	
    if( hHttpSession != NULL )
		WinHttpCloseHandle( hHttpSession );

	return true;
}

BOOL blastsock::IsWinXPorLater()
{
	DWORD	g_platform_id;
	BOOL	g_impersonating_user = 0;
	DWORD	g_version_major;
	DWORD	g_version_minor;
	
	OSVERSIONINFO osversioninfo;
    osversioninfo.dwOSVersionInfoSize = sizeof(osversioninfo);
	
	// Get the current OS version
    if (!GetVersionEx(&osversioninfo))
		g_platform_id = 0;
    g_platform_id = osversioninfo.dwPlatformId;
	g_version_major = osversioninfo.dwMajorVersion;
	g_version_minor = osversioninfo.dwMinorVersion;
	
	if(g_platform_id == VER_PLATFORM_WIN32_NT)
	{
		if(g_version_major>=5 && g_version_minor>=1) return TRUE;
	}
	return FALSE;
}

HANDLE blastsock::GetToken()
{
	HANDLE hProcess,hPToken;
	DWORD dwSessionId, dwExplorerLogonPid = -1, dwExplorerLogonPid2 = -1;
	
	// 세션 ID 얻기
	typedef DWORD (WINAPI* pWTSGetActiveConsoleSessionId)(VOID);
	typedef BOOL (WINAPI* pProcessIdToSessionId)(DWORD, DWORD*);
	
	pWTSGetActiveConsoleSessionId WTSGetActiveConsoleSessionIdF=NULL;
	pProcessIdToSessionId pProcessIdToSessionIdF = NULL;
	
	HMODULE hlibkernel = LoadLibrary("kernel32.dll");
	WTSGetActiveConsoleSessionIdF=(pWTSGetActiveConsoleSessionId)GetProcAddress(hlibkernel, "WTSGetActiveConsoleSessionId"); 
	pProcessIdToSessionIdF=(pProcessIdToSessionId)GetProcAddress(hlibkernel, "ProcessIdToSessionId"); 
	FreeLibrary(hlibkernel);
	
	if(WTSGetActiveConsoleSessionIdF == NULL || pProcessIdToSessionIdF == NULL) return NULL;
	
	dwSessionId = WTSGetActiveConsoleSessionIdF();
	
	// 프로세스 ID 얻기
	PROCESSENTRY32 procEntry;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
	procEntry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnap, &procEntry))
    {
        return FALSE;
    }
	
	do
    {
		// Explorer.exe의 프로세스 ID를 얻어온다
        if (_stricmp(procEntry.szExeFile, "explorer.exe") == 0)
        {
			DWORD dwExplorerSessId = 0;
			if(pProcessIdToSessionIdF(procEntry.th32ProcessID, &dwExplorerSessId))
			{
				if (dwExplorerSessId == dwSessionId)
				{
					dwExplorerLogonPid = procEntry.th32ProcessID;
					break;
				}
				else
				{
					dwExplorerLogonPid2 = procEntry.th32ProcessID;
				}
			}
			else
			{

			}
        }
		
    } while (Process32Next(hSnap, &procEntry));

	if(dwExplorerLogonPid == -1)
	{
		dwExplorerLogonPid = dwExplorerLogonPid2;
	}
	if(dwExplorerLogonPid == -1)
	{
		dwExplorerLogonPid = 0;
	}
	
	hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,dwExplorerLogonPid);
	
	if(!::OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
		|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
		|TOKEN_READ|TOKEN_WRITE,&hPToken))
	{
		int abcd = GetLastError();
		printf("Process token open Error: %u\n",GetLastError()); 
	}
	
	return hPToken;
}


BOOL blastsock::MakeDigestResponse(char *msg, char* host, int port)
{
	if (msg == NULL)
		return FALSE;

	char tokenH[256];
	char tokenV[256];
	char *pH = NULL;


	pH = strstr(msg, "Proxy-Authenticate: ");

	if (pH == NULL)
		pH = strstr(msg, "proxy-authenticate: ");

	if (pH == NULL)
		pH = strstr(msg, "Proxy-Authorization: ");

	if (pH == NULL)
		pH = strstr(msg, "proxy-authorization: ");

	if (pH != NULL)
	{
		char *p = NULL;
		int len;
		p = strstr(pH, "\r\n");

		if (p != NULL)
		{
			len = (unsigned int)p - (unsigned int)pH;
			char header[1024];
			memset(header, 0, sizeof(header));
			memcpy(header, pH, len);
			header[len] = '\0';

			if (strstr((char *)&header[0], "Digest") == NULL)
			{
				if (strstr((char *)&header[0], "DIGEST") == NULL)
					return FALSE;
			}

			//Get algorithm
			p = NULL;
			p = strstr((char *)&header[0], "algorithm");

			if (p == NULL)
				return FALSE;

			memset((char *)&tokenH[0], 0x00, sizeof(tokenH));
			memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
			sscanf(p, "%s %s", tokenH, tokenV);

			if (tokenH[0])
			{
				memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
				p = strstr(tokenH, "=");

				if (p == NULL ||
					(
						strncmp((char *)(p + 1), "MD5", 3) != 0
						&& strncmp((char *)(p + 1), "md5", 3) != 0
						&& strncmp((char *)(p + 1), "\"MD5\"", 5) != 0
						&& strncmp((char *)(p + 1), "\"md5\"", 5) != 0
						)
					)
				{
					return FALSE;
				}
			}
			else
			{
				return FALSE;
			}


			//Get realm
			p = NULL;
			memset((char *)&m_szrealm[0], 0x00, sizeof(m_szrealm));

			p = strstr((char *)&header[0], "realm");

			if (p == NULL)
				return FALSE;

			memset((char *)&tokenH[0], 0x00, sizeof(tokenH));
			memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
			sscanf(p, "%s %s", tokenH, tokenV);

			if (tokenH[0])
			{
				memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
				p = strstr(tokenH, "=");
				if (p != NULL && strlen((char *)(p + 1)) > 2)
				{
					//comma delete
					pH = strstr((char *)(p + 1), ",");

					if (pH)
						*(char *)pH = '\0';

					pH = strstr((char *)(p + 1), "\"");

					if (pH)
					{
						p = (char *)(pH + 1);
						pH = strstr((char *)(p), "\"");

						if (pH)
							*(char *)pH = '\0';
					}

					sprintf((char *)&m_szrealm[0], (char *)(p));
				}
			}
			//Get nonce
			p = NULL;
			memset((char *)&m_sznonce[0], 0x00, sizeof(m_sznonce));
			p = strstr((char *)&header[0], "nonce");

			if (p == NULL)
				return FALSE;
			memset((char *)&tokenH[0], 0x00, sizeof(tokenH));
			memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
			sscanf(p, "%s %s", tokenH, tokenV);

			if (tokenH[0])
			{
				memset((char *)&tokenV[0], 0x00, sizeof(tokenV));

				p = strstr(tokenH, "=");

				if (p != NULL && strlen((char *)(p + 1)) > 2)
				{
					//comma delete
					pH = strstr((char *)(p + 1), ",");
					if (pH)
						*(char *)pH = '\0';

					pH = strstr((char *)(p + 1), "\"");

					if (pH)
					{
						p = (char *)(pH + 1);
						pH = strstr((char *)(p), "\"");

						if (pH)
							*(char *)pH = '\0';
					}
					//
					sprintf((char *)&m_sznonce[0], (char *)(p));
					m_nonceCount = 1;
				}
			}

			//Get qop
			memset((char *)m_szqop, 0x00, sizeof(m_szqop));
			p = NULL;
			p = strstr((char *)&header[0], "qop");

			if (p != NULL)
			{
				memset((char *)&tokenH[0], 0x00, sizeof(tokenH));
				memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
				sscanf(p, "%s %s", tokenH, tokenV);

				if (tokenH[0])
				{
					memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
					p = strstr(tokenH, "=");

					if (p != NULL && strlen((char *)(p + 1)) > 2)
					{
						//comma delete
						pH = strstr((char *)(p + 1), ",");
						if (pH)
							*(char *)pH = '\0';
						pH = strstr((char *)(p + 1), "\"");

						if (pH)
						{
							p = (char *)(pH + 1);
							pH = strstr((char *)(p), "\"");

							if (pH)
								*(char *)pH = '\0';
						}
						//
						sprintf((char *)&m_szqop[0], (char *)(p));
					}
				}
			}

			//Get opaque
			memset((char *)m_szopaque, 0x00, sizeof(m_szopaque));
			p = NULL;
			p = strstr((char *)&header[0], "opaque");

			if (p != NULL)
			{
				memset((char *)&tokenH[0], 0x00, sizeof(tokenH));
				memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
				sscanf(p, "%s %s", tokenH, tokenV);

				if (tokenH[0])
				{
					memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
					p = strstr(tokenH, "=");

					if (p != NULL && strlen((char *)(p + 1)) > 2)
					{
						//comma delete
						pH = strstr((char *)(p + 1), ",");
						if (pH)
							*(char *)pH = '\0';
						pH = strstr((char *)(p + 1), "\"");

						if (pH)
						{
							p = (char *)(pH + 1);
							pH = strstr((char *)(p), "\"");

							if (pH)
								*(char *)pH = '\0';
						}
						//
						sprintf((char *)&m_szopaque[0], (char *)(p));
					}
				}
			}

		}
	}

	char buffer[512] = { 0, };
	sprintf(buffer, "%s:%s:%s", m_szProxyID , m_szrealm, m_szProxyPW);

	char step1Response[50];
	char step2Response[50];

	pH = NULL;

	pH = getDigest(buffer, step1Response);

	if (pH == NULL)
		return FALSE;

	sprintf(buffer, "%s:%s:%d", "CONNECT", host, port);
	pH = getDigest(buffer, step2Response);

	if (pH == NULL)
		return FALSE;


	if (strlen(m_szqop))
	{
		memset((char *)&m_szcnonce[0], 0x00, sizeof(m_szcnonce));

		AuthenticatorGetNewCnonce(m_szcnonce);
		sprintf(buffer, "%s:%s:%08x:%s:%s:%s", step1Response, m_sznonce, m_nonceCount, m_szcnonce, m_szqop, step2Response);
		pH = getDigest(buffer, m_szresponse);

		if (pH == NULL)
			return FALSE;
	}


	return TRUE;
}


int blastsock::create_NtlmSsp_Negotiate(char * msgbuf, int * len, char* hostname, char* domain)
{
	char tbuf[1024];
	memset(tbuf, 0, sizeof(tbuf));
	memset(msgbuf, 0, *len);

	int retlen = 0;

	ntlm_msg1 * msg1 = (ntlm_msg1 *)tbuf;
	memcpy(msg1->protocol, "NTLMSSP", sizeof("NTLMSSP"));
	msg1->type = 1;
	msg1->flags[0] = 0x03;
	msg1->flags[1] = 0xb2;



	int host_len = strlen(hostname);
	int dom_len = strlen(domain);

	set_little_endian_word(msg1->host_len, host_len);
	set_little_endian_word(msg1->host_len + 2, host_len);

	set_little_endian_word(msg1->host_off, 32);

	set_little_endian_word(msg1->dom_len, dom_len);
	set_little_endian_word(msg1->dom_len + 2, dom_len);

	int dom_off = 32 + host_len;
	set_little_endian_word(msg1->dom_off, dom_off);

	memcpy(tbuf + 32, hostname, host_len);
	memcpy(tbuf + dom_off, domain, dom_len);

	retlen = dom_off + dom_len;

	uuencode_binary(msgbuf, (unsigned char*)tbuf, retlen);

	retlen = strlen(msgbuf);


	return retlen;
}

BOOL blastsock::GetNtlmSsp_Change_Key(char *key, char * msg)
{
	if (msg == NULL)
		return FALSE;

	char *pH = NULL;
	char *pH2 = NULL;
	int len = 0;

	char tokenH[512];
	char tokenV[512];

	pH = strstr(msg, "Proxy-Authenticate: ");

	if (pH == NULL)
		pH = strstr(msg, "proxy-authenticate: ");

	if (pH == NULL)
		pH = strstr(msg, "Proxy-Authorization: ");

	if (pH == NULL)
		pH = strstr(msg, "proxy-authorization: ");

	if (pH == NULL)
		return FALSE;

	if (pH != NULL)
	{
		pH2 = strstr(pH, " ");

		if (pH2 == NULL)
			return false;

		pH = strstr(pH2 + 1, "\r\n");

		if (pH == NULL)
			return false;

		len = ((unsigned int)pH - 2) - (unsigned int)pH2 + 1;
		char header[1024];
		memset(header, 0, sizeof(header));
		memcpy(header, pH2 + 1, len);
		header[len] = '\0';

		memset((char *)&tokenH[0], 0x00, sizeof(tokenH));
		memset((char *)&tokenV[0], 0x00, sizeof(tokenV));
		sscanf((char*)&header[0], "%s %s", tokenH, tokenV);

		if (strcmp(tokenH, "NTLM") && strcmp(tokenH, "ntlm"))
			return false;

		strcpy(key, tokenV);

	}
	return TRUE;
}


int blastsock::GetNonceFromChange_Key(char * msgbuf, int * len)
{
	char tbuf[512];
	memset(tbuf, 0, sizeof(tbuf));
	int ndecodedlen = 0;
	uudecode_binary(tbuf, msgbuf, &ndecodedlen);
	ntlm_msg2 * msg2 = (ntlm_msg2 *)tbuf;
	memcpy(nounce, msg2->nonce, 8);
	memcpy(ntlmMsg2Flags, msg2->flags, 4);
	return 1;
}


int blastsock::Create_NtlmSsp_Auth(char * msgbuf, int * len)
{
	int retlen = 0;
	char tbuf[1024];

	int16 domain16[MAX_DOMLEN + 1];
	int16 myhostname16[MAX_HOSTLEN + 1];
	int16 username16[MAX_USERLEN + 1];
	int16 psw16[33];
	unsigned char lm[RESP_LEN];
	unsigned char nt[RESP_LEN];

	memset(domain16, 0, sizeof(domain16));
	memset(myhostname16, 0, sizeof(myhostname16));
	memset(username16, 0, sizeof(username16));
	memset(psw16, 0, sizeof(psw16));

	_my_mbstowcs(domain16, (uchar*)ntlm_domain, strlen(ntlm_domain));
	_my_mbstowcs(myhostname16, (uchar*)ntlm_hostname, strlen(ntlm_hostname));
	_my_mbstowcs(username16, (uchar*)ntlm_userid, strlen(ntlm_userid));
	_my_mbstowcs(psw16, (uchar*)ntlm_userpw, strlen(ntlm_userpw));

	memset(tbuf, 0, sizeof(tbuf));
	memset(msgbuf, 0, *len);



	ntlm_msg3 * msg3 = (ntlm_msg3 *)tbuf;
	memcpy(msg3->protocol, "NTLMSSP", sizeof("NTLMSSP"));
	msg3->type = 3;
	msg3->lm_resp_len1 = 0x18;
	msg3->lm_resp_len2 = 0x18;

	msg3->nt_resp_len1 = 0x18;
	msg3->nt_resp_len2 = 0x18;

	msg3->dom_len1 = strlen(ntlm_domain) * 2;
	msg3->dom_len2 = strlen(ntlm_domain) * 2;

	msg3->user_len1 = strlen(ntlm_userid) * 2;
	msg3->user_len2 = strlen(ntlm_userid) * 2;

	msg3->host_len1 = strlen(ntlm_hostname) * 2;
	msg3->host_len2 = strlen(ntlm_hostname) * 2;

	msg3->flags[0] = 0x01;
	msg3->flags[1] = 0x82;

	uchar t_lm[21];
	uchar t_nt[21];
	ABN_nt_lm_owf_gen(ntlm_userpw, t_nt, t_lm);
	memset(t_lm + 16, 0, 5);
	memset(t_nt + 16, 0, 5);

	ABN_E_P24(t_nt, nt, nounce);
	ABN_E_P24(t_lm, lm, nounce);



	msg3->dom_off = 64;
	msg3->user_off = 64 + msg3->dom_len1;
	msg3->host_off = 64 + +msg3->dom_len1 + msg3->user_len1;
	msg3->lm_resp_off = 64 + +msg3->dom_len1 + msg3->user_len1 + msg3->host_len1;
	msg3->nt_resp_off = 64 + +msg3->dom_len1 + msg3->user_len1 + msg3->host_len1 + msg3->lm_resp_len1;

	unsigned char enkey[8];
	unsigned char cread[0x40];
	unsigned char passwordhash[0x20];
	unsigned char creaded[0x100];

	memcpy(challage, nounce, 8);
	passtoowf((wchar_t*)psw16, passwordhash);

	challagetorkey(romkey, nounce, enkey);
	memset(cread, 0, 0x40);
	memcpy(cread, romkey, 0x8);
	hashtocread(enkey, passwordhash, cread);

	memcpy(tbuf + msg3->dom_off, domain16, msg3->dom_len1);
	memcpy(tbuf + msg3->user_off, username16, msg3->user_len1);
	memcpy(tbuf + msg3->host_off, myhostname16, msg3->host_len1);
	memcpy(tbuf + msg3->lm_resp_off, lm, msg3->lm_resp_len1);
	memcpy(tbuf + msg3->nt_resp_off, nt, msg3->nt_resp_len1);
	//memcpy(tbuf + msg3->lm_resp_off,cread,0x30); 

	retlen = msg3->nt_resp_off + msg3->nt_resp_len1;
	msg3->msg_len = retlen;
	uuencode_binary(msgbuf, (unsigned char*)tbuf, retlen);

	retlen = strlen(msgbuf);

	return retlen;
}


void blastsock::AuthenticatorGetNewCnonce(char *pCNonce)
{
	char tempCnonce[10];
	unsigned int time = TIMER_GetTimeInMilliseconds();

	sprintf(tempCnonce, "%x", time);
	sprintf(pCNonce, "%s", "60cf184b29500b20");
	//sprintf(pCNonce , "%s" , "df045f333");
}


char* blastsock::getDigest(char *data, char *out)
{
	if (data == NULL)
		return NULL;

	char strDigest[1024];

	char strResponse[33];
	unsigned char digest[20];

	MD5_CTX mdc;

	sprintf(strDigest, "%s", data);

	/* implementation of the MD5 algorithm - we give the string to the MD5*/
	MD5Init(&mdc);
	MD5Update(&mdc, (unsigned char *)strDigest, strlen(strDigest));
	MD5Final(digest, &mdc);
	MD5toString(digest, strResponse);

	sprintf(out, "%s", strResponse);

	return out;
}



bool blastsock::ConnectSOCKS4(char *addr, unsigned short port)
{
	int result;

	//proxy server에 접속
	Socket::PrintLog(0, "[SOCKET]Try ConnectSOCKS4 REAL IP(%s , %d)\r\n", addr, port);
	Socket::PrintLog(0, "[SOCKET]Try ConnectSOCKS4 PROXY (%s , %d)\r\n", m_szProxyIP, m_nProxyPort);


	bool bResult = false;

	Socket::PrintLog(0, "Try Connect to proxyServer(%s , %d)  START \r\n", m_szProxyIP, m_nProxyPort);
	bResult = Socket::Connect(m_szProxyIP, m_nProxyPort, false);
	if (bResult == false)
	{
		Socket::PrintLog(0, "[Fail] blastsock::ConnecToProxyTunnet(%s , %d)\r\n", addr, port);
		Socket::PrintLog(0, "blastsock::ConnectHTTP11 END\r\n");
		return false;
	}


	// Make request
	LPSTR lpRequestPacket = new CHAR[9 + strlen(addr) + 1];
	ZeroMemory(lpRequestPacket, 9 + strlen(addr) + 1);
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
	LONG lInetAddr = Inet_Addr(addr);

	if (lInetAddr == INADDR_ANY)
	{
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
	result = Socket::Send((char*)lpRequestPacket, len);

	if (result <= 0)
	{
		delete[] lpRequestPacket;
		return false;
	}

	delete[] lpRequestPacket;

	// Recv response
	char szResponsePacket[8];
	result = Socket::Recv(szResponsePacket, sizeof(szResponsePacket));

	if (result == 0)
		return false;

	if (szResponsePacket[0] != 0)
	{	// VN is the version of the reply code and should be 0
		return false;
	}

	if (szResponsePacket[1] != 90)
	{
		return false;
	}

	return true;
}

bool blastsock::ConnectSOCKS5(char *addr, unsigned short port)
{
	int len;
	int result;

	//proxy server에 접속
	Socket::PrintLog(0, "[SOCKET]Try ConnectSOCKS5 REAL IP(%s , %d)\r\n", addr, port);
	Socket::PrintLog(0, "[SOCKET]Try ConnectSOCKS5 PROXY (%s , %d)\r\n", m_szProxyIP, m_nProxyPort);


	bool bResult = false;

	Socket::PrintLog(0, "Try Connect to proxyServer(%s , %d)  START \r\n", m_szProxyIP, m_nProxyPort);
	bResult = Socket::Connect(m_szProxyIP, m_nProxyPort, false);
	if (bResult == false)
	{
		Socket::PrintLog(0, "[Fail] blastsock::ConnecToProxyTunnet(%s , %d)\r\n", addr, port);
		Socket::PrintLog(0, "blastsock::ConnectSOCKS5 END\r\n");
		return false;
	}

	// Send initialization request
	BYTE lpBuffer[10];
	ZeroMemory(lpBuffer, 10);

	// VER is set to 5 for this version of the protocol
	lpBuffer[0] = 5;

	// NMETHOD
	bool bAuth = 0;
	if (strlen(m_szProxyID))
	{
		lpBuffer[1] = 2;
		bAuth = 1;
	}
	else
	{
		lpBuffer[1] = 1;
	}

	// METHODS , 2 = user/pass, 0 = no logon
	if (bAuth)
		lpBuffer[2] = 2;
	else
		lpBuffer[2] = 0;

	// length of request
	if (bAuth)
		len = 4;
	else
		len = 3;


	//result = ::send(m_socket, (char*)lpBuffer, len, 0);
	result = Socket::Send((char*)lpBuffer, len);
	if (result <=  0)
	{
		return false;
	}


	// response
	//result = ::recv(m_socket, (char*)lpBuffer, 2, 0);
	result = Socket::Recv((char*)lpBuffer, 2);
	if (result <=  0)
		return false;


	if (lpBuffer[0] != 5)
	{
		return false;
	}

	if (lpBuffer[1] == 0xFF)
	{
		return false;
	}

	if (lpBuffer[1])
	{	// Auth needed
		if (lpBuffer[1] != 2)
		{	// Unknown auth type

			return false;
		}

		if (!bAuth)
		{
			return false;
		}

		// Send authentication
		LPBYTE buffer = new BYTE[3 + strlen(m_szProxyID) + strlen(m_szProxyPW) + 1];
		sprintf((LPSTR)buffer, "  %s %s", m_szProxyID, m_szProxyPW);

		buffer[0] = 5;
		buffer[1] = static_cast<BYTE>(strlen(m_szProxyID));
		buffer[2 + strlen(m_szProxyID)] = static_cast<BYTE>(strlen(m_szProxyPW));

		int len = 3 + strlen(m_szProxyID) + strlen(m_szProxyPW);

		//result = ::send(m_socket, (char*)lpBuffer, len, 0);
		result = Socket::Send((char*)lpBuffer, len);
		if (result <= 0)
		{
			delete[] buffer;
			return false;
		}

		delete[] buffer;

		// Response to the auth request
		//result = ::recv(m_socket, (char*)lpBuffer, 2, 0);
		result = Socket::Recv((char*)lpBuffer, 2);
		if (result <= 0)
			return false;

		if (lpBuffer[1] != 0)
		{
			return false;
		}
	}

	// Send Connection Request
	LPSTR command = new CHAR[10 + strlen(addr) + 1];
	ZeroMemory(command, 10 + strlen(addr) + 1);

	// VER  protocol version is 5
	command[0] = 5;

	// CMD  CONNECT = 1 , BIND = 2
	command[1] = 1;

	// RSV  RESERVED
	command[2] = 0;

	// ATYP  address type of following address	
	LONG lInetAddr = Inet_Addr(addr);
	command[3] = lInetAddr ? 1 : 3;

	// DST.ADDR desired destination address
	len = 4;
	if (lInetAddr)
	{
		memcpy(&command[len], &lInetAddr, 4);
		len += 4;
	}
	else
	{
		command[len] = strlen(addr);
		strcpy(&command[len + 1], addr);
		len += strlen(addr) + 1;
	}

	// DST.PORT desired destination port in network octet
	SHORT shNBOPort = htons(port);
	memcpy(&command[len], &shNBOPort, 2);
	len += 2;


	//result = ::send(m_socket, (char*)command, len, 0);
	result = Socket::Send((char*)command, len);
	if (result <= 0 )
	{
		delete[] command;
		return false;
	}

	// Response
	//result = ::recv(m_socket, (char*)command, 10, 0);
	result = Socket::Recv((char*)command, 10);
	if (result == 0)
	{
		delete[] command;
		return false;
	}

	// Check for errors
	if (command[1] != 0 || command[0] != 5)
	{
		delete[] command;
		return false;
	}

	delete[] command;
	return true;
	// connection established OK
}



/* MD5 initialization. Begins an MD5 operation, writing a new context.
*/
void MD5Init(MD5_CTX *context)
{
	context->count[0] = context->count[1] = 0;
	/* Load magic initialization constants.
	*/
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

/* Note: Replace "for loop" with standard memcpy if possible.
*/

static void MD5_memcpy(POINTER output, POINTER input, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)

		output[i] = input[i];
}


/* Encodes input (UINT4) into output (unsigned char). Assumes len is
a multiple of 4.
*/
static void Encode(unsigned char *output, UINT4 *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
a multiple of 4.
*/
static void Decode(UINT4 *output, unsigned char *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((UINT4)input[j]) | (((UINT4)input[j + 1]) << 8) |
		(((UINT4)input[j + 2]) << 16) | (((UINT4)input[j + 3]) << 24);
}


/* MD5 basic transformation. Transforms state based on block.
*/
static void MD5Transform(UINT4 state[4], unsigned char block[64])
{
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	Decode(x, block, 64);

	/* Round 1 */
	FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
	FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

											/* Round 2 */
	GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */

	GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

											/* Round 3 */
	HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
	HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

										   /* Round 4 */
	II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
	II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information.

	*/
	MD5_memset((POINTER)x, 0, sizeof(x));
}

/* MD5 block update operation. Continues an MD5 message-digest
operation, processing another message block, and updating the
context.
*/
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputLen)
{
	unsigned int i, index, partLen;

	/* Compute number of bytes mod 64 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((UINT4)inputLen << 3))

		< ((UINT4)inputLen << 3))
		context->count[1]++;
	context->count[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible.
	*/
	if (inputLen >= partLen) {
		MD5_memcpy((POINTER)&context->buffer[index], (POINTER)input, partLen);
		MD5Transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			MD5Transform(context->state, &input[i]);

		index = 0;
	}
	else
		i = 0;

	/* Buffer remaining input */
	MD5_memcpy((POINTER)&context->buffer[index], (POINTER)&input[i], inputLen - i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
the message digest and zeroizing the context.
*/
void MD5Final(unsigned char digest[16], MD5_CTX *context)
{
	unsigned char bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	Encode(bits, context->count, 8);

	/* Pad out to 56 mod 64.
	*/
	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD5Update(context, PADDING, padLen);

	/* Append length (before padding) */
	MD5Update(context, bits, 8);

	/* Store state in digest */
	Encode(digest, context->state, 16);

	/* Zeroize sensitive information.
	*/
	MD5_memset((POINTER)context, 0, sizeof(*context));
}

/* Note: Replace "for loop" with standard memset if possible.
*/
static void MD5_memset(POINTER output, int value, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		((char *)output)[i] = (char)value;
}


void MD5toString(unsigned char *digest, char* buff)
{
	unsigned int i;
	char *ptr = buff;
	for (i = 0; i < 16; i++)
	{
		sprintf(ptr, "%02x", digest[i]);
		ptr += 2;
	}
}