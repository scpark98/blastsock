#ifndef WININETDOWNLOADER_H
#define WININETDOWNLOADER_H

// using WinINet
#include<Wininet.h>

class WinINetDownLoader  
{
public:
	WinINetDownLoader();
	virtual ~WinINetDownLoader();

	BOOL InternetOpen(LPCTSTR lpszAgent, 
		              DWORD dwAccessType = INTERNET_OPEN_TYPE_PRECONFIG, 
					  LPCTSTR lpszProxyName = NULL, 
					  LPCTSTR lpszProxyBypass = NULL, 
					  DWORD dwFlags = 0,
					  HKEY hKeyParent = HKEY_CURRENT_USER,
					  LPCSTR lpszKeyName = NULL);

	BOOL InternetConnect(LPCTSTR lpszServerName, // host server name
						 INTERNET_PORT nServerPort = INTERNET_DEFAULT_HTTP_PORT, // host server port
						 LPCTSTR lpszUsername = NULL,
						 LPCTSTR lpszPassword = NULL, 
						 DWORD dwService = INTERNET_SERVICE_HTTP,
						 DWORD dwFlags = 0,
						 DWORD dwContext = 0);

	BOOL HttpOpenRequest(LPCTSTR lpszObjectName,	
						 LPCTSTR lpszReferer = NULL,				 
						 LPCTSTR lpszVerb = NULL,
						 LPCTSTR lpszVersion = NULL,
						 LPCTSTR* lpszAcceptTypes = NULL,
						 DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION,
						 DWORD_PTR dwContext = 0);

	BOOL HttpSendRequest(LPCTSTR lpszHeaders = NULL, // 추가 header
						 DWORD dwHeadersLength = 0, // header 의 길이
						 LPVOID lpOptional = NULL, // post 의 데이터
						 DWORD dwOptionalLength = 0); // post 데이터의 길이

	BOOL InternetReadFile(LPVOID lpBuffer,
						  DWORD dwNumberOfBytesToRead,
						  LPDWORD lpdwNumberOfBytesRead);
	
	BOOL HttpQueryInfo(DWORD dwInfoLevel,
					   LPVOID lpvBuffer,
					   LPDWORD lpdwBufferLength,
					   LPDWORD lpdwIndex);

	BOOL InternetSetOption(DWORD dwOption, 
							LPVOID lpszBuffer, 
							DWORD dwBufferLength);

	void InternetCloseHandle();
	void InternetCloseInternetHandle();
	void InternetCloseConnectHandle();
	void InternetCloseRequestHandle();
protected:
	HINTERNET m_hInternet;
	HINTERNET m_hConnect;
	HINTERNET m_hRequest;

private:
	BOOL m_bSSL;
};

#endif // #ifndef WININETDOWNLOADER_H
