#ifndef BLASTSOCK_BLASTSOCK_H
#define BLASTSOCK_BLASTSOCK_H

//#include "ProxyInfo.h"
//#include "ProxySocket.h"
#include "Socket.h"
#include "neturoCrypto.h"
#include "blastsocklib.h"
#include "StringQueue.h"

#define BLASTSOCK_PROXYTUNNELING		0
#define BLASTSOCK_PROXYQUERY			1
#define BLASTSOCK_NO_PROXYTUNNELING		2
#define BLASTSOCK_PROXYTUNNELING_MANUAL 3
#define BLASTSOCK_CRYPT_CREATEAESKEY	0 // NMS 가 CS , Viewer 와 통신할때
#define BLASTSOCK_CRYPT_RECVAESKEY		1 // CS , Viewer 가 NMS 랑 통신할때 
#define BLASTSOCK_CRYPT					2 // 그외에 비밀키를 가지고 있을경우 암호화
#define BLASTSOCK_NO_CRYPT				3 // 암호화하지않을때
#define BLASTSOCK_NO_BUFFER				0
#define BLASTSOCK_BUFFER				1

// ERROR CODE
// USE WSAGetLastError();
#define BLASTSOCK_ERROR_PARAMETER				(WSABASEERR + 11000)
#define BLASTSOCK_ERROR_CRYPTBUFFEROVERFLOW		(WSABASEERR + 11001)
#define BLASTSOCK_ERROR_CRYPTBUFFEREMPTY		(WSABASEERR + 11002)
#define BLASTSOCK_ERROR_CRYPT					(WSABASEERR + 11003)

// ws2_32.lib wininet.lib urlmon.lib Advapi32.lib Shell32.lib 를 include 해준다

class blastsock : public Socket 
{
public:
	blastsock();
	blastsock(blastsock* s);
	virtual ~blastsock();

	bool CryptInit(int crypt = BLASTSOCK_NO_CRYPT, neturoCrypto* cryptlib = NULL, RSAKey* rsakey = NULL);
	bool CryptCreateAESKey();
	bool CryptRecvAESKey(RSAKey* rsakey = NULL);

	// PROXY Tunneling connect

	bool FindProxyFromWinHttp();
	bool TunnelingInit(unsigned int tunneling = BLASTSOCK_NO_PROXYTUNNELING,
					   //CProxyInfo* pProxyInfo = NULL,
					   void* pProxyInfo = NULL,
					   bool fromIE = false,
					   bool regsave = false,
					   bool cfileown = false,
					   HKEY hKeyParent = HKEY_CURRENT_USER, 
					   LPCSTR lpszKeyName = NULL);
	bool IsProxyEnv();
	bool Connect(char *addr, unsigned int port);

	// AES 암호화 적용 SEND , RECV
	bool SendExact(const char* buf, unsigned int bufLen, unsigned int usebuf = BLASTSOCK_NO_BUFFER);
	bool RecvExact(char* buf, unsigned int bufLen, unsigned int usebuf = BLASTSOCK_NO_BUFFER, int flags = 0);

	bool CheckManualProxy(HKEY hKeyParent, LPCSTR lpszKeyName);

	bool StartLog(LPTSTR filename = NULL , bool bEncrypt = true);

	void CheckProxyEnvironment(HKEY hKeyParent, LPCSTR lpszKeyName);
	bool WinInetConnect(char *strRetVal, int nRetValSize, char *strAgent, char *strServerAddr, int nServerPort, char *strUrl, HKEY hKeyParent, LPCSTR lpszKeyName);

private :
	BOOL IsWinXPorLater();
	HANDLE GetToken();
	BOOL GetLogPath(TCHAR * savePath);
protected:
	// Proxy Tunneling Variable
	int m_tunnelingmode;
	//CProxyInfo* m_pProxyinfo;	// 프록시 환경 판단 및 서버 얻어오기
	bool m_proxyinfoown;		// 
	//CProxyData* m_pProxydata;	// Proxy Server Address Array
	int m_proxydataLen;
	
	// AES Crypt Variable
	int m_cryptmode;			// 암호화 하는지 여부
	neturoCrypto* m_pCryptlib;	// 실제 암호화 담당
	bool m_cryptown;			// m_cryptlib 를 클래스내에서 생성했는지여부
	StringQueue* m_pCryptqueue;		// 버퍼링 모드일때 사용하는 버퍼
	char* m_lpSendCryptBuf;
	char* m_lpRecvCryptBuf;
	char* m_lpRecvCryptBuf2;
	static const int CRYPTBUFFERSIZE;
//	CProxyData* m_pSelectedProxyData;
	bool m_bManualProxy;


	//proxy tunneling
	int m_bUseProxy;
	char m_szProxyIP[64];
	char m_szProxyID[32];
	char m_szProxyPW[32];
	int m_nProxyPort;


	bool ConnecToProxyTunnel(char* host, int port);
	bool ConnectHTTP11(char *host, unsigned short port);
	bool ConnectSOCKS4(char *host, unsigned short port);
	bool ConnectSOCKS5(char *host, unsigned short port);

	BOOL MakeDigestResponse(char *msg, char* host, int port);
	void	AuthenticatorGetNewCnonce(char	*pCNonce);
	char*	getDigest(char	*data, char	*out);

	//Digest Auth
	char				m_szrealm[50];
	char				m_sznonce[150];
	char				m_szcnonce[150];
	char				m_szresponse[256];
	int					m_nonceCount;
	char				m_szqop[50];
	char				m_szopaque[50];

	//NTLM
	char ntlm_hostname[256];
	char ntlm_domain[256];
	char ntlm_userid[256];
	char ntlm_userpw[256];

	byte  ntlmMsg2Flags[4];
	unsigned char  nounce[8];
	BOOL GetNtlmSsp_Change_Key(char *key, char * msg);

	int create_NtlmSsp_Negotiate(char * msgbuf, int * len, char* hostname, char* domain);
	int GetNonceFromChange_Key(char * msgbuf, int * len);
	int Create_NtlmSsp_Auth(char * msgbuf, int * len);
	
};

#endif // #ifndef BLASTSOCK_BLASTSOCK_H