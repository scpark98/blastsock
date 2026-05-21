#ifndef BLASTSOCK_BLASTSOCK_H
#define BLASTSOCK_BLASTSOCK_H

//#include "ProxyInfo.h"
#include "ProxySocket.h"
#include "neturoCrypto.h"
#include "blastsocklib.h"
#include "StringQueue.h"

#define BLASTSOCK_PROXYTUNNELING		0
#define BLASTSOCK_PROXYQUERY			1
#define BLASTSOCK_NO_PROXYTUNNELING		2
#define BLASTSOCK_PROXYTUNNELING_MANUAL 3
#define BLASTSOCK_CRYPT_CREATEAESKEY	0 // NMS가 CS, Viewer에 접속할때
#define BLASTSOCK_CRYPT_RECVAESKEY		1 // CS, Viewer가 NMS에 접속할때
#define BLASTSOCK_CRYPT					2 // 그외에 대칭키가 이미지 생성되어 암호화
#define BLASTSOCK_NO_CRYPT				3 // 암호화사용안함
#define BLASTSOCK_NO_BUFFER				0
#define BLASTSOCK_BUFFER				1
#define BLASTSOCK_PROXYTUNNELING_DIRECTCONNECT_FIRST	1	// 20170725 [서비스 접속 속도 개선]
#define BLASTSOCK_PROXYTUNNELING_PROXYCONNECT_FIRST		2	// 20170725 [서비스 접속 속도 개선]


// ERROR CODE
// USE WSAGetLastError();
#define BLASTSOCK_ERROR_PARAMETER				(WSABASEERR + 11000)
#define BLASTSOCK_ERROR_CRYPTBUFFEROVERFLOW		(WSABASEERR + 11001)
#define BLASTSOCK_ERROR_CRYPTBUFFEREMPTY		(WSABASEERR + 11002)
#define BLASTSOCK_ERROR_CRYPT					(WSABASEERR + 11003)

// ws2_32.lib wininet.lib urlmon.lib Advapi32.lib Shell32.lib을 include 해준다

class blastsock : public ProxySocket
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
	bool Connect(const char *addr, unsigned int port);
    bool ConnectDirect(const char* addr, unsigned int port); // 20170725 [서비스 접속 속도 개선]
    bool ConnectProxy(const char* addr, unsigned int port);   // 20170725 [서비스 접속 속도 개선]

	// AES 암호화 적용 SEND, RECV
	bool SendExact(const char* buf, unsigned int bufLen, unsigned int usebuf = BLASTSOCK_NO_BUFFER);
	bool RecvExact(char* buf, unsigned int bufLen, unsigned int usebuf = BLASTSOCK_NO_BUFFER, int flags = 0);

	bool CheckManualProxy(HKEY hKeyParent, LPCSTR lpszKeyName);

	bool StartLog(LPTSTR filename = NULL , bool bEncrypt = true);

	void CheckProxyEnvironment(HKEY hKeyParent, LPCSTR lpszKeyName);
	bool WinInetConnect(char *strRetVal, int nRetValSize, char *strAgent, char *strServerAddr, int nServerPort, char *strUrl, HKEY hKeyParent, LPCSTR lpszKeyName);
	void SetProxyTunnelingConnectionOption(int proxytunnelingConnectOption) { m_proxytunnelingConnectOption = proxytunnelingConnectOption; }	// 20170725 [서비스 접속 속도 개선]
	int GetProxyTunnelingConnectionOption() { return m_proxytunnelingConnectOption; }						// 20170725 [서비스 접속 속도 개선]

private :
	BOOL IsWinXPorLater();
	HANDLE GetToken();
protected:
	// Proxy Tunneling Variable
	int m_tunnelingmode;
	//CProxyInfo* m_pProxyinfo;	// 프록시 환경 판단 시 사용 데이터
	bool m_proxyinfoown;		//
	CProxyData* m_pProxydata;	// Proxy Server Address Array
	int m_proxydataLen;

	// AES Crypt Variable
	int m_cryptmode;			// 암호화 하는지 여부
	neturoCrypto* m_pCryptlib;	// 실제 암호화 라이브러리
	bool m_cryptown;			// m_cryptlib을 클래스에서 생성했는지 여부
	StringQueue* m_pCryptqueue;	// 버퍼를 사용할때 사용하는 큐
	char* m_lpSendCryptBuf;
	char* m_lpRecvCryptBuf;
	char* m_lpRecvCryptBuf2;
	static const int CRYPTBUFFERSIZE;
	CProxyData* m_pSelectedProxyData;
	bool m_bManualProxy;

	int m_proxytunnelingConnectOption; // 20170725 [서비스 접속 속도 개선] : proxy로 접속 시 direct / proxy중 어느 방식을 먼저 시도할지 결정하는 모드
									   // 최초에는 socket을 갖고 있는 Process의 처음에 설정된 모드를 사용하고 이후 socket마다 설정되어 있는 모드를 그대로 사용한다.
};

#endif // #ifndef BLASTSOCK_BLASTSOCK_H
