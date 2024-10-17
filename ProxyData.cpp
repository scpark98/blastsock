 // ProxyData.cpp: implementation of the CProxyData class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ProxyData.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////


CProxyData::CProxyData()
{
	m_dwType = PROXYTYPE_NOPROXY;
	m_lpHost = m_lpUser = m_lpPass = m_lpDestinationHost = NULL;
	m_shPort = m_shDestinationPort = 0;
	m_bAuth  = FALSE;
	
}

CProxyData::~CProxyData()
{
	if(m_lpHost != NULL) delete [] m_lpHost;
	if(m_lpUser != NULL) delete [] m_lpUser;
	if(m_lpPass != NULL) delete [] m_lpPass;
	if(m_lpDestinationHost != NULL) delete [] m_lpDestinationHost;
}

BOOL CProxyData::SetType(DWORD dwType)
{
	// Validate the parameters
	if(dwType != PROXYTYPE_SOCKS4 && dwType != PROXYTYPE_SOCKS4A && 
	   dwType != PROXYTYPE_SOCKS5 && dwType != PROXYTYPE_HTTP11 && dwType != PROXYTYPE_HTTP11QUERY &&dwType != PROXYTYPE_NOPROXY)
		return FALSE;

	m_dwType = dwType;
	return TRUE;
}

DWORD CProxyData::GetType()
{
	return m_dwType; 
}

BOOL CProxyData::SetProxyHost(LPSTR lpHost)
{
	// Validate the parameters
	if(lpHost == NULL || strlen(lpHost) == 0)  return FALSE;

	if(m_lpHost != NULL) { delete [] m_lpHost; m_lpHost = NULL; }
	m_lpHost = _strdup(lpHost);
	return TRUE;
}

LPSTR CProxyData::GetProxyHost() 
{
	return m_lpHost; 
}

BOOL CProxyData::SetProxyPort(SHORT shPort)
{
	// Validate the parameters
	if(shPort <= 0 || shPort > 65535) return FALSE;

	m_shPort = shPort;
	return TRUE;
}

SHORT CProxyData::GetProxyPort()
{
	return m_shPort; 
}

BOOL CProxyData::SetUser(LPSTR lpUser)
{
	// Validate the parameters
	if(lpUser == NULL || strlen(lpUser) == 0)  return FALSE;

	if(m_lpUser != NULL) { delete [] m_lpUser; m_lpUser = NULL; }
	m_lpUser = _strdup(lpUser);
	return TRUE;
}

LPSTR CProxyData::GetUser()
{
	return m_lpUser;
}

BOOL CProxyData::SetPass(LPSTR lpPass)
{
	// Validate the parameters
	if(lpPass == NULL || strlen(lpPass) == 0)  return FALSE;

	if(m_lpPass != NULL) { delete [] m_lpPass; m_lpPass = NULL; }
	m_lpPass = _strdup(lpPass);
	return TRUE;
}

LPSTR CProxyData::GetPass()
{
	return m_lpPass; 
}

BOOL CProxyData::SetAuth(BOOL bAuth)
{
	m_bAuth = bAuth;
	return TRUE;
}

BOOL CProxyData::GetAuth()
{
	return m_bAuth; 
}

BOOL CProxyData::SetDestinationHost(LPCSTR lpHost)
{
	// Validate the parameters
	if(lpHost == NULL || strlen(lpHost) == 0)  return FALSE;

	if(m_lpDestinationHost != NULL) { delete [] m_lpDestinationHost; m_lpDestinationHost = NULL; }
	m_lpDestinationHost = _strdup(lpHost);
	return TRUE;
}

LPSTR CProxyData::GetDestinationHost() 
{
	return m_lpDestinationHost; 
}

BOOL CProxyData::SetDestinationPort(SHORT shPort)
{
	// Validate the parameters
	if(shPort <= 0 || shPort > 65535) return FALSE;

	m_shDestinationPort = shPort;
	return TRUE;
}

SHORT CProxyData::GetDestinationPort()
{
	return m_shDestinationPort; 
}

CProxyData& CProxyData::operator= (CProxyData& rhs)
{
	if(this == &rhs) return *this;

	SetAuth(rhs.GetAuth());
	SetProxyHost(rhs.GetProxyHost());
	SetPass(rhs.GetPass());
	SetProxyPort(rhs.GetProxyPort());
	SetType(rhs.GetType());
	SetUser(rhs.GetUser());
	SetDestinationHost(rhs.GetDestinationHost());
	SetDestinationPort(rhs.GetDestinationPort());
	return *this;
}

