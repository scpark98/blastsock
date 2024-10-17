#ifndef BLASTSOCK_PROXYINFO_H
#define BLASTSOCK_PROXYINFO_H

// ProxyInfo.h
// proxy 정보를 얻어온다

// proxy 환경
#define PROXYENV_UNKNOWN		0x00000000
#define PROXYENV_DIRECT			0x000000ff
#define PROXYENV_PROXY			0x0000ff00
#define PROXYENV_AUTOPROXY		0x00ff0000

#include "ProxyData.h"


class CProxyInfo  
{
public:
	CProxyInfo();
	virtual ~CProxyInfo();

	// 익스플로러의 레지스트리에서 프록시 환경을 읽어온다
	void LoadProxyEnvFromExplorer(bool cfileown = false);
	// 사용자가 지정한 레지스트리에서 프록시 환경을 읽어온다
	void LoadProxyEnv(HKEY hKeyParent, LPCSTR lpszKeyName, bool cfileown = false);
	// 현재의 프록시 설정을 지정한 레지스트리에 저장한다
	void SaveProxyEnv(HKEY hKeyParent, LPCSTR lpszKeyName);

	// proxy 환경을 리턴한다
	DWORD GetProxyEnv();

	// Proxy Server 의 정보를 초기화한다
	void InitProxyServerData(LPSTR lpUrl, LPSTR lpHost, CProxyData** ppProxyData, int& nProxyData);

private:
	void InitDirectData(CProxyData** ppProxyData, INT& nProxyData);
	void InitProxyData(CProxyData** ppProxyData, INT& nProxyData);
	void InitAutoProxyData(LPSTR lpUrl, LPSTR lpHost, CProxyData** ppProxyData, INT& nProxyData);

	BOOL GetAutoProxyServer(LPSTR lpProxyHostName, LPDWORD lpdwProxyHostNameLength, LPSTR lpUrl, LPSTR lpHost);
	
	// Helper Function
	static DWORD WINAPI ResolveHostName(LPSTR lpszHostName, LPSTR lpszIPAddress, LPDWORD lpdwIPAddressSize);
	static BOOL  WINAPI IsResolvable(LPSTR lpszHost);
	static DWORD WINAPI GetIPAddress(LPSTR lpszIPAddress, LPDWORD lpdwIPAddressSize);
	static BOOL  WINAPI IsInNet(LPSTR lpszIPAddress, LPSTR lpszDest, LPSTR lpszMask);

	DWORD m_dwProxyEnv;		// proxy 환경
	char* m_cfile;			// Auto-Proxy Configuration File Name
	bool m_cfileown;
	char* m_proxyserver;	// proxy server list

	CRITICAL_SECTION m_cs;	// for thread safe
};

#endif // #ifndef BLASTSOCK_PROXYINFO_H