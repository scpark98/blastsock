// WinINetDownLoader.cpp: implementation of the WinINetDownLoader class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "WinINetDownLoader.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* https */
#define __W3_DEFAULT_AGENT "Mozilla/4.0 (compatible; )"
#define __HTTP_VERB_GET	"GET"
#define __HTTP_VERB_POST "POST"
#define __HTTP_ACCEPT_TYPE "*/*"
#define __HTTP_ACCEPT "Accept: */*\r\n"
#define __DEFAULT_BUF_SIZE 1024
/* https */


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

WinINetDownLoader::WinINetDownLoader()
{	
	m_hInternet = NULL;
	m_hConnect = NULL;
	m_hRequest = NULL;

	m_bSSL = FALSE;
}

WinINetDownLoader::~WinINetDownLoader()
{
	InternetCloseHandle();
}

BOOL WinINetDownLoader::InternetOpen(LPCTSTR lpszAgent, DWORD dwAccessType, LPCTSTR lpszProxyName, LPCTSTR lpszProxyBypass, DWORD dwFlags, HKEY hKeyParent, LPCSTR lpszKeyName)
{
	if(m_hInternet != NULL) InternetCloseInternetHandle();
	m_hInternet = ::InternetOpen(lpszAgent, dwAccessType, lpszProxyName, lpszProxyBypass, dwFlags);
	if(m_hInternet == NULL) return FALSE;
	else return TRUE;
}

BOOL WinINetDownLoader::InternetConnect(LPCTSTR lpszServerName, INTERNET_PORT nServerPort, LPCTSTR lpszUsername, LPCTSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD dwContext)
{
	if(m_hConnect != NULL) InternetCloseConnectHandle();
	m_hConnect = ::InternetConnect(m_hInternet, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext);
	if(nServerPort == 443) m_bSSL = TRUE;
	else m_bSSL = FALSE;

	if(m_hConnect == NULL) return FALSE;
	else return TRUE;
}

BOOL WinINetDownLoader::HttpOpenRequest(LPCTSTR lpszObjectName, LPCTSTR lpszReferer, LPCTSTR lpszVerb, LPCTSTR lpszVersion, LPCTSTR* lpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
	if(m_hRequest != NULL) InternetCloseRequestHandle();

	if(m_bSSL == FALSE)
	{
		m_hRequest = ::HttpOpenRequest(m_hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lpszAcceptTypes, dwFlags, dwContext);
		::HttpAddRequestHeaders( m_hRequest ,	__HTTP_ACCEPT, strlen(__HTTP_ACCEPT),	HTTP_ADDREQ_FLAG_REPLACE) ;
	}
	else
	{
		static LPCTSTR szAcceptType = TEXT(__HTTP_ACCEPT_TYPE);
		m_hRequest = ::HttpOpenRequest(m_hConnect, __HTTP_VERB_GET, lpszObjectName, HTTP_VERSION, lpszReferer, &szAcceptType, INTERNET_FLAG_SECURE, NULL);
		::HttpAddRequestHeaders( m_hRequest ,	__HTTP_ACCEPT, strlen(__HTTP_ACCEPT),	HTTP_ADDREQ_FLAG_REPLACE) ;
	}
	if(m_hRequest == NULL) return FALSE;
	else return TRUE;
}

BOOL WinINetDownLoader::HttpSendRequest(LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	return ::HttpSendRequest(m_hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WinINetDownLoader::InternetReadFile(LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
	return ::InternetReadFile(m_hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL WinINetDownLoader::HttpQueryInfo(DWORD dwInfoLevel, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex)
{
	return ::HttpQueryInfo(m_hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex);
}

BOOL WinINetDownLoader::InternetSetOption(DWORD dwOption, LPVOID lpszBuffer, DWORD dwBufferLength)
{
	return ::InternetSetOption(m_hRequest, dwOption, lpszBuffer, dwBufferLength); 
}

void WinINetDownLoader::InternetCloseHandle()
{
	InternetCloseInternetHandle();
	InternetCloseConnectHandle();
	InternetCloseRequestHandle();
}

void WinINetDownLoader::InternetCloseInternetHandle()
{
	::InternetCloseHandle(m_hInternet);
	m_hInternet = NULL;
}

void WinINetDownLoader::InternetCloseConnectHandle()
{
	::InternetCloseHandle(m_hConnect);
	m_hConnect = NULL;
}

void WinINetDownLoader::InternetCloseRequestHandle()
{
	::InternetCloseHandle(m_hRequest);
	m_hRequest = NULL;
}
