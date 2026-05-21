#ifndef BLASTSOCK_PROXYSOCKET_H
#define BLASTSOCK_PROXYSOCKET_H

// ProxySocket.h
// proxy tunneling을 자동으로 해주는 소켓

#include "socket.h"
#include "ProxyData.h"
#include "NTLM.h"

#define PROXYSOCKET_ERROR_NOCONN				(WSABASEERR + 10000) // Can't connect to proxy server
#define PROXYSOCKET_ERROR_REQUESTFAILED			(WSABASEERR + 10001) // Request failed, can't send data
#define PROXYSOCKET_ERROR_AUTHREQUIRED			(WSABASEERR + 10003) // Authentication required
#define PROXYSOCKET_ERROR_AUTHTYPEUNKNOWN		(WSABASEERR + 10004) // Authtype unknown or not supported
#define PROXYSOCKET_ERROR_AUTHFAILED			(WSABASEERR + 10005) // Authentication failed
#define PROXYSOCKET_ERROR_AUTHNOLOGON			(WSABASEERR + 10006)
#define PROXYSOCKET_ERROR_CANTRESOLVEHOST		(WSABASEERR + 10007)



class ProxySocket : public Socket 
{
public:
	ProxySocket();
	virtual ~ProxySocket();

	void SetProxyData(CProxyData& ProxyData);

	bool Connect(const char *addr, unsigned int port);

	// Send시 HTTP query 자체를 인자로 준다
	bool SendHTTPQuery(LPCSTR lpHTTPQuery, INT dwTotalBytesSend);

	static BOOL CALLBACK ProxyAuthDlgProc(HWND hwndDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

	bool WinInetConnect(char *strRetVal, int nRetValSize, char *strAgent, char *strServerAddr, int nServerPort, char *strUrl);

	// 20170809 : 407에러 일때 Proxy 정보 표시
	bool GetProxyIPPortIfUnAuthorized(char * ip, char * port);

protected:
    bool ConnectNOPROXY(const char* addr, unsigned int port);
	bool ConnectSOCKS4(const char* addr, unsigned int port);
    bool ConnectSOCKS5(const char* addr, unsigned int port);
	bool ConnectHTTP11(const char* addr, unsigned int port);

	CProxyData m_ProxyData;

	NTLM m_ntlm;
	bool m_proxyUnAuthorized; // 20170809 : 407에러 일때 Proxy 정보 표시
};


#endif // #ifndef BLASTSOCK_PROXYSOCKET_H
