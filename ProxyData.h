#ifndef BLASTSOCK_PROXYDATA_H
#define BLASTSOCK_PROXYDATA_H

// ProxyData.h
// proxy server 의 정보를 저장한다

// Proxy types
#define PROXYTYPE_NOPROXY		0
#define PROXYTYPE_SOCKS4		1
#define PROXYTYPE_SOCKS4A		2
#define PROXYTYPE_SOCKS5		3
#define PROXYTYPE_HTTP11		4
#define PROXYTYPE_HTTP11QUERY	5

class CProxyData
{
public:
	CProxyData();
	virtual ~CProxyData();

	BOOL   SetType(DWORD dwType);
	DWORD  GetType();

	BOOL   SetProxyHost(LPSTR lpHost);
	LPSTR  GetProxyHost();

	BOOL   SetProxyPort(SHORT shPort);
	SHORT  GetProxyPort();

	BOOL   SetUser(LPSTR lpUser);
	LPSTR  GetUser();

	BOOL   SetPass(LPSTR lpPass);
	LPSTR  GetPass();

	BOOL   SetAuth(BOOL bAuth);
	BOOL   GetAuth();

	BOOL   SetDestinationHost(LPCSTR lpHost);
	LPSTR  GetDestinationHost();

	BOOL   SetDestinationPort(SHORT shPort);
	SHORT  GetDestinationPort();

	CProxyData& operator= (CProxyData&);
protected:
	DWORD m_dwType;	// Proxy type
	LPSTR m_lpHost;	// Proxy Host
	SHORT m_shPort;	// Proxy Pory
	LPSTR m_lpUser;	// Proxy User ID
	LPSTR m_lpPass;	// Proxy User Password
	BOOL  m_bAuth;  // Proxy Authentication ( use proxy user id or password )

	LPSTR m_lpDestinationHost;
	SHORT m_shDestinationPort;
};

#endif // #ifndef BLASTSOCK_PROXYDATA_H
