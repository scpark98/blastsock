#ifndef BLASTSOCK_PROXYSOCKET_H
#define BLASTSOCK_PROXYSOCKET_H

// ProxySocket.h
// proxy tunneling 을 자동으로 해주는 소켓

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

	bool Connect(char *addr, unsigned int port);

	// Send 할 HTTP query 전체를 인자로 준다
	bool SendHTTPQuery(LPCSTR lpHTTPQuery, INT dwTotalBytesSend);

	static BOOL CALLBACK ProxyAuthDlgProc(HWND hwndDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

	bool WinInetConnect(char *strRetVal, int nRetValSize, char *strAgent, char *strServerAddr, int nServerPort, char *strUrl);


	
protected:
	bool ConnectNOPROXY(char *addr, unsigned int port);
	bool ConnectSOCKS4(char *addr, unsigned int port);
	bool ConnectSOCKS5(char *addr, unsigned int port);
	bool ConnectHTTP11(char *addr, unsigned int port);

	CProxyData m_ProxyData;

	//NTLM m_ntlm;

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


#endif // #ifndef BLASTSOCK_PROXYSOCKET_H
