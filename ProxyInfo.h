#ifndef BLASTSOCK_PROXYINFO_H
#define BLASTSOCK_PROXYINFO_H

// ProxyInfo.h
// proxy ������ ���´�

// proxy ȯ��
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

	// �ͽ��÷η��� ������Ʈ������ ���Ͻ� ȯ���� �о�´�
	void LoadProxyEnvFromExplorer(bool cfileown = false);
	// ����ڰ� ������ ������Ʈ������ ���Ͻ� ȯ���� �о�´�
	void LoadProxyEnv(HKEY hKeyParent, LPCSTR lpszKeyName, bool cfileown = false);
	// ������ ���Ͻ� ������ ������ ������Ʈ���� �����Ѵ�
	void SaveProxyEnv(HKEY hKeyParent, LPCSTR lpszKeyName);

	// proxy ȯ���� �����Ѵ�
	DWORD GetProxyEnv();

	// Proxy Server �� ������ �ʱ�ȭ�Ѵ�
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

	DWORD m_dwProxyEnv;		// proxy ȯ��
	char* m_cfile;			// Auto-Proxy Configuration File Name
	bool m_cfileown;
	char* m_proxyserver;	// proxy server list

	CRITICAL_SECTION m_cs;	// for thread safe
};

#endif // #ifndef BLASTSOCK_PROXYINFO_H