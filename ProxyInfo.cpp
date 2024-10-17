// ProxyInfo.cpp: implementation of the CProxyInfo class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ProxyInfo.h"
#include <io.h>
#include <stdlib.h>
#include <wininet.h>
#include <urlmon.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atlbase.h> // for registry



#define REG_SUBKEY      "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define REG_PROXYENABLE "ProxyEnable"
#define REG_PROXYSERVER "ProxyServer"
#define REG_AUTOCONFIG  "AutoConfigURL"
#define REG_CFILENAME   "CFileName"


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CProxyInfo::CProxyInfo()
{
	InitializeCriticalSection(&m_cs);
	m_dwProxyEnv = PROXYENV_UNKNOWN;
	m_cfile = m_proxyserver = NULL;
	m_cfileown = false;
}

CProxyInfo::~CProxyInfo()
{
	DeleteCriticalSection(&m_cs);

	if(m_proxyserver) delete [] m_proxyserver;
	if(m_cfile) 
	{
		if(m_cfileown) DeleteFile(m_cfile);
		delete [] m_cfile;
	}
}

void CProxyInfo::LoadProxyEnvFromExplorer(bool cfileown)
{
//	kLog->Print(2 , "CProxyInfo::LoadProxyEnvFromExplorer(cfileown : %d) start\r\n" , cfileown);

	EnterCriticalSection(&m_cs);

	CRegKey RegKey;
	DWORD dwData;
	DWORD dwDataSize;
	char RegistryQueryValue[1024];

	// 변수 초기화
	m_dwProxyEnv = PROXYENV_UNKNOWN;
	if(m_proxyserver) 
	{
		delete [] m_proxyserver;
		m_proxyserver = NULL;
	}
	if(m_cfile) 
	{
		if(m_cfileown) DeleteFile(m_cfile);
		delete [] m_cfile;
		m_cfile = NULL;
	}

	m_cfileown = cfileown;

	// 레지스트리를 연다
	if(RegKey.Open(HKEY_CURRENT_USER, REG_SUBKEY, KEY_READ) != ERROR_SUCCESS) 
	{
		LeaveCriticalSection(&m_cs);
		return;
	}
		
	// 프록시 체크
	dwDataSize = 1024;
	ZeroMemory(RegistryQueryValue, 1024);
	if(RegKey.QueryValue(dwData, REG_PROXYENABLE) == ERROR_SUCCESS && dwData == 1
	   && RegKey.QueryValue(RegistryQueryValue, REG_PROXYSERVER, &dwDataSize) == ERROR_SUCCESS
	   && dwDataSize != 0)
	{
		m_proxyserver = _strdup(RegistryQueryValue);
		m_dwProxyEnv = m_dwProxyEnv | PROXYENV_PROXY;

	//	kLog->Print(3 , "GetProxyInfo(%s : %d)\r\n" , m_proxyserver , m_dwProxyEnv);
	}

	
	// 오토프록시 체크
	dwDataSize = 1024;
	ZeroMemory(RegistryQueryValue, dwDataSize);
	if(RegKey.QueryValue(RegistryQueryValue, REG_AUTOCONFIG, &dwDataSize) == ERROR_SUCCESS 
	   && dwDataSize != 0)
	{
		
		char TempPath[MAX_PATH];
		m_cfile = new char[MAX_PATH];
		ZeroMemory(TempPath, MAX_PATH);
		ZeroMemory(m_cfile, MAX_PATH);

		
		// 윈도우즈의 임시 파일 이름을 얻어온다
		if(GetTempPath(sizeof(TempPath)/sizeof(TempPath[0]), TempPath)
		   && GetTempFileName(TempPath, "Neturo", 0, m_cfile)
		   && URLDownloadToFile(NULL, RegistryQueryValue, m_cfile, NULL, NULL) == S_OK)
		{
			m_dwProxyEnv = m_dwProxyEnv | PROXYENV_AUTOPROXY;		
		}
		else
		{
			delete [] m_cfile;
			m_cfile = NULL;
		}
	}

	RegKey.Close();
	LeaveCriticalSection(&m_cs);

	//kLog->Print(3 , "CProxyInfo::LoadProxyEnvFromExplorer() end\r\n");
	
}

void CProxyInfo::LoadProxyEnv(HKEY hKeyParent, LPCSTR lpszKeyName, bool cfileown)
{
	//	kLog->Print(2 , "CProxyInfo::LoadProxyEnv() start( %s , %d) start\r\n" , lpszKeyName , cfileown);
	EnterCriticalSection(&m_cs);

	CRegKey RegKey;
	DWORD dwDataSize;
	char RegistryQueryValue[1024];

	// 변수 초기화
	m_dwProxyEnv = PROXYENV_UNKNOWN;
	if(m_proxyserver) 
	{
		delete [] m_proxyserver;
		m_proxyserver = NULL;
	}
	if(m_cfile) 
	{
		if(m_cfileown) DeleteFile(m_cfile);
		delete [] m_cfile;
		m_cfile = NULL;
	}

	m_cfileown = cfileown;

	// 레지스트리를 연다
	if(RegKey.Open(hKeyParent, lpszKeyName, KEY_READ) != ERROR_SUCCESS) 
	{
		LeaveCriticalSection(&m_cs);
		return;
	}

	// 프록시 체크
	dwDataSize = 1024;
	ZeroMemory(RegistryQueryValue, 1024);
	if(RegKey.QueryValue(RegistryQueryValue, REG_PROXYSERVER, &dwDataSize) == ERROR_SUCCESS
	   && dwDataSize != 0)
	{
		m_proxyserver = _strdup(RegistryQueryValue);
		m_dwProxyEnv = m_dwProxyEnv | PROXYENV_PROXY;
	
	//		kLog->Print(3 , "GetProxyInfo(%s : %d)\r\n" , m_proxyserver , m_dwProxyEnv);
	}

	// 오토프록시 체크
	dwDataSize = 1024;
	ZeroMemory(RegistryQueryValue, dwDataSize);
	if(RegKey.QueryValue(RegistryQueryValue, REG_CFILENAME, &dwDataSize) == ERROR_SUCCESS 
	   && dwDataSize != 0 && _access(RegistryQueryValue, 0) != -1)
	{
		m_cfile = _strdup(RegistryQueryValue);
		m_dwProxyEnv = m_dwProxyEnv | PROXYENV_AUTOPROXY;
	
	//		kLog->Print(3 , "GetProxyInfo AutoProxy(cfile: %s : %d)\r\n" , m_cfile , m_dwProxyEnv);
	}
	RegKey.Close();

	LeaveCriticalSection(&m_cs);
	
	//	kLog->Print(2 , "CProxyInfo::LoadProxyEnv() end\r\n");
}

void CProxyInfo::SaveProxyEnv(HKEY hKeyParent, LPCSTR lpszKeyName)
{
	//	kLog->Print(2 , "CProxyInfo::SaveProxyEnv(lpszKeyName : %s) Start\r\n" , lpszKeyName);

	CRegKey RegKey;

	// 레지스트리를 연다
	if(RegKey.Create(hKeyParent, lpszKeyName) != ERROR_SUCCESS) return;
	if(RegKey.Open(hKeyParent, lpszKeyName, KEY_ALL_ACCESS) != ERROR_SUCCESS) return;
		
	// 레지스트리 초기화
	DWORD dwDataSize = 1024;
	char RegistryQueryValue[1024];
	ZeroMemory(RegistryQueryValue, dwDataSize);
	if(RegKey.QueryValue(RegistryQueryValue, REG_CFILENAME, &dwDataSize) == ERROR_SUCCESS 
	&& dwDataSize != 0 && _access(RegistryQueryValue, 0) != -1)
	{
		DeleteFile(RegistryQueryValue);
	}
	RegKey.DeleteValue(REG_PROXYSERVER);
	RegKey.DeleteValue(REG_CFILENAME);	

	// 프록시 저장
	if((m_dwProxyEnv & PROXYENV_PROXY) == PROXYENV_PROXY && m_proxyserver)
	{
		RegKey.SetValue(m_proxyserver, REG_PROXYSERVER);
	
	//	kLog->Print(3 , "Save Proxy(%s)\r\n" , m_proxyserver);
	}

	// 오토프록시 저장
	if((m_dwProxyEnv & PROXYENV_AUTOPROXY) == PROXYENV_AUTOPROXY && m_cfile)
	{
		RegKey.SetValue(m_cfile, REG_CFILENAME);
	
	//	kLog->Print(3 , "Save AutoProxy(%s)\r\n" , m_cfile);
	}

	RegKey.Close();

	//		kLog->Print(2 , "CProxyInfo::SaveProxyEnv() End\r\n");
}

DWORD CProxyInfo::GetProxyEnv()
{
	return m_dwProxyEnv;
}

void CProxyInfo::InitProxyServerData(LPSTR lpUrl, LPSTR lpHost, CProxyData** ppProxyData, int& nProxyData)
{
	// 변수 초기화
	nProxyData = 0;
	if(*ppProxyData != NULL)
	{ 
		delete [] *ppProxyData;
		*ppProxyData = NULL;
	}

	// 오토프록시 초기화
	if((m_dwProxyEnv & PROXYENV_AUTOPROXY) == PROXYENV_AUTOPROXY)
	{
		InitAutoProxyData(lpUrl, lpHost, ppProxyData, nProxyData);
	}
	
	// 프록시 초기화
	if((m_dwProxyEnv & PROXYENV_PROXY) == PROXYENV_PROXY)
	{
		InitProxyData(ppProxyData, nProxyData);
	}

	// 그냥 맨 마지막에는 direct 로 채워준다
	InitDirectData(ppProxyData, nProxyData);
}

void CProxyInfo::InitDirectData(CProxyData** ppProxyData, INT& nProxyData)
{
	if(*ppProxyData == NULL) 
	{
		nProxyData = 0;
		*ppProxyData = new CProxyData[1];
	}
	
	// 이미 DIRECT 가 있는지 검사한다
	for(int i=0; i<nProxyData; i++)
	{
		if((*ppProxyData)[i].GetType() == PROXYTYPE_NOPROXY) return;
	}

	(*ppProxyData)[nProxyData++].SetType(PROXYTYPE_NOPROXY);
}

void CProxyInfo::InitProxyData(CProxyData** ppProxyData, INT& nProxyData)
{
	if(*ppProxyData == NULL) 
	{
		nProxyData = 0;
		*ppProxyData = new CProxyData[3];
	}

	// 프록시 서버의 리스트 문자열을 복제해놓는다
	char proxyserver[512];
	ZeroMemory(proxyserver, 512);
	strcpy(proxyserver, m_proxyserver);

	// IP 와 PORT 를 파싱한다
	LPSTR token = NULL;
	token = strtok(proxyserver, ";");
	while(token != NULL)
	{
		if(strlen(token) > 5 && !strncmp(token, "http=", 5)) 
		{	// HTTP
			(*ppProxyData)[nProxyData].SetType(PROXYTYPE_HTTP11);
			token+=5;
		}
		else if(strlen(token) > 6 && !strncmp(token, "socks=", 6)) 
		{	// SOCKS
			(*ppProxyData)[nProxyData].SetType(PROXYTYPE_SOCKS4);
			token+=6;
		}
		else if(strlen(token) > 4 && !strncmp(token, "ftp=", 4)) 
		{
			token = strtok(NULL, ";");
			continue;
			// ftp proxy 지원안함.
		}
		else if(strlen(token) > 7 && !strncmp(token, "gopher=", 7)) 
		{
			token = strtok(NULL, ";");
			continue;
			// gopher proxy 지원안함.
		}
		else if(strlen(token) > 6 && !strncmp(token, "https=", 6)) 
		{
			token = strtok(NULL, ";");
			continue;
			// https proxy 지원안함.
		}
		else if(strlen(token) > 1/* && token[0] >= '0' && token[0] <= '9'*/)
		{	// 모든 경우 같은 경우. 그냥 HTTP 로 작동하게 했다. 후에 이상있을지도 모르겠네.
			(*ppProxyData)[nProxyData].SetType(PROXYTYPE_HTTP11);
		}
		else 
		{
			token = strtok(NULL, ";");
			continue;
		}
		
		for(int i=1; i<(int)strlen(token)-1; i++)
		{
			if(token[i] == ':') 
			{
				token[i] = '\0';
				(*ppProxyData)[nProxyData].SetProxyHost(token);
				(*ppProxyData)[nProxyData].SetProxyPort((SHORT)atoi(token+i+1));
				nProxyData++;
				break;
			}
		}
		token = strtok(NULL, ";");
	}
}

void CProxyInfo::InitAutoProxyData(LPSTR lpUrl, LPSTR lpHost, CProxyData** ppProxyData, INT& nProxyData)
{
	DWORD dwCFILEReturnValueLength;
	CHAR CFILEReturnValue[1024];		
	ZeroMemory(CFILEReturnValue, 1024);
	
	// CFILE 을 이용해 proxy server list 를 얻어온다
	if(!GetAutoProxyServer(CFILEReturnValue, &dwCFILEReturnValueLength, lpUrl, lpHost))
	{
		return;
	}

	// 개수센다
	for(DWORD i=0; i<dwCFILEReturnValueLength; i++)
	{
		if(CFILEReturnValue[i] == ';') nProxyData++;
	}

	// 변수초기화
	*ppProxyData = new CProxyData[nProxyData+4];
	nProxyData = 0;

	// 파싱
	LPSTR token  = NULL;
	token = strtok(CFILEReturnValue, ";");

	while(token != NULL)
	{
		// ltrim
		while(strlen(token) > 0 && token[0] == ' ') token++;

		if(strlen(token) > 6 && !strncmp(token, "PROXY ", 6))
		{	// HTTP PROXY
			(*ppProxyData)[nProxyData].SetType(PROXYTYPE_HTTP11);
			token += 6;
		}
		else if(strlen(token) > 6 && !strncmp(token, "SOCKS ", 6))
		{	// SOCKS PROXY
			(*ppProxyData)[nProxyData].SetType(PROXYTYPE_SOCKS4);
			token += 6;
		}
		else if(strlen(token) > 6 && !strncmp(token, "DIRECT", 6))
		{	// NO PROXY
			(*ppProxyData)[nProxyData++].SetType(PROXYTYPE_NOPROXY);
			token = strtok(NULL, ";");
			continue;
		}
		else if(nProxyData == 0)
		{	// index = 0 , 맨 처음에 proxy server 의 종류가 써있지 않은거. 에러처리할까하다가 이런경우에는 무조건 HTTP 프록시로 인식하도록했다
			(*ppProxyData)[nProxyData].SetType(PROXYTYPE_HTTP11);
		}
		else
		{	// proxy server 의 종류가 안써져있을경우. 바로 이전것과 통일
			(*ppProxyData)[nProxyData].SetType((*ppProxyData)[nProxyData-1].GetType());
		}

		// ltrim
		while(strlen(token) > 0 && token[0] == ' ') token++;
			
		for(int i=1; i<(int)strlen(token)-1; i++)
		{
			if(token[i] == ':') 
			{
				token[i] = '\0';
				(*ppProxyData)[nProxyData].SetProxyHost(token);
				(*ppProxyData)[nProxyData].SetProxyPort((SHORT)atoi(token+i+1));
				nProxyData++;
				break;
			}
		}
		token = strtok(NULL, ";");
	}
}

/////////////////////////////////////////////////////////////////////
//  ResolveHostName                               (a helper function)
/////////////////////////////////////////////////////////////////////
DWORD WINAPI CProxyInfo::ResolveHostName(LPSTR lpszHostName, LPSTR lpszIPAddress, LPDWORD lpdwIPAddressSize)
{
	DWORD dwIPAddressSize;
	addrinfo Hints;
	LPADDRINFO lpAddrInfo;
	LPADDRINFO IPv4Only;
	DWORD error;

	// Figure out first whether to resolve a name or an address literal.
	// If getaddrinfo( ) with the AI_NUMERICHOST flag succeeds, then
	// lpszHostName points to a string representation of an IPv4 or IPv6 
	// address. Otherwise, getaddrinfo( ) should return EAI_NONAME.
	ZeroMemory( &Hints, sizeof(addrinfo) );
	Hints.ai_flags    = AI_NUMERICHOST;  // Only check for address literals.
	Hints.ai_family   = PF_UNSPEC;       // Accept any protocol family.
	Hints.ai_socktype = SOCK_STREAM;     // Constrain results to stream socket.
	Hints.ai_protocol = IPPROTO_TCP;     // Constrain results to TCP.

	error = getaddrinfo( lpszHostName, NULL, &Hints, &lpAddrInfo );
	if( error != EAI_NONAME )
	{
		if( error != 0 )
		{
			error = ( error == EAI_MEMORY ) ?
			ERROR_NOT_ENOUGH_MEMORY : ERROR_INTERNET_NAME_NOT_RESOLVED;
			goto quit;
		}
		freeaddrinfo( lpAddrInfo );

		// An IP address (either v4 or v6) was passed in, so if there is 
		// room in the lpszIPAddress buffer, copy it back out and return.
		dwIPAddressSize = lstrlen( lpszHostName );

		if( ( *lpdwIPAddressSize < dwIPAddressSize ) ||
		( lpszIPAddress == NULL ) )
		{
			*lpdwIPAddressSize = dwIPAddressSize + 1;
			error = ERROR_INSUFFICIENT_BUFFER;
			goto quit;
		}
		lstrcpy( lpszIPAddress, lpszHostName );
		goto quit;
	}

	// Call getaddrinfo( ) again, this time with no flag set.
	Hints.ai_flags = 0;
	error = getaddrinfo( lpszHostName, NULL, &Hints, &lpAddrInfo );
	if( error != 0 )
	{
		error = ( error == EAI_MEMORY ) ?
		ERROR_NOT_ENOUGH_MEMORY : ERROR_INTERNET_NAME_NOT_RESOLVED;
		goto quit;
	}

	// Convert the IP address in addrinfo into a string.
	// (the following code only handles IPv4 addresses)
	IPv4Only = lpAddrInfo;
	while( IPv4Only->ai_family != AF_INET )
	{
		IPv4Only = IPv4Only->ai_next;
		if( IPv4Only == NULL )
		{
			error = ERROR_INTERNET_NAME_NOT_RESOLVED;
			goto quit;
		}
	}
	error = getnameinfo( IPv4Only->ai_addr, IPv4Only->ai_addrlen, lpszIPAddress,
			*lpdwIPAddressSize, NULL, 0, NI_NUMERICHOST );
	if( error != 0 )
		error = ERROR_INTERNET_NAME_NOT_RESOLVED;
quit:
	return(error);
}


/////////////////////////////////////////////////////////////////////
//  IsResolvable                                  (a helper function)
/////////////////////////////////////////////////////////////////////
BOOL WINAPI CProxyInfo::IsResolvable( LPSTR lpszHost )
{
	char szDummy[255];
	DWORD dwDummySize = sizeof(szDummy) - 1;

	if( ResolveHostName( lpszHost, szDummy, &dwDummySize ) )
		return( FALSE );
	return TRUE;
}


/////////////////////////////////////////////////////////////////////
//  GetIPAddress                                  (a helper function)
/////////////////////////////////////////////////////////////////////
DWORD WINAPI CProxyInfo::GetIPAddress(LPSTR lpszIPAddress, LPDWORD lpdwIPAddressSize)
{
	char szHostBuffer[255];

	if( gethostname( szHostBuffer, sizeof(szHostBuffer) - 1 ) != ERROR_SUCCESS )
		return( ERROR_INTERNET_INTERNAL_ERROR );
	return( ResolveHostName( szHostBuffer, lpszIPAddress, lpdwIPAddressSize ) );
}


/////////////////////////////////////////////////////////////////////
//  IsInNet                                       (a helper function)
/////////////////////////////////////////////////////////////////////
BOOL WINAPI CProxyInfo::IsInNet( LPSTR lpszIPAddress, LPSTR lpszDest, LPSTR lpszMask )
{
	DWORD dwDest;
	DWORD dwIpAddr;
	DWORD dwMask;

	dwIpAddr = inet_addr( lpszIPAddress );
	dwDest   = inet_addr( lpszDest );
	dwMask   = inet_addr( lpszMask );

	if( ( dwDest == INADDR_NONE ) ||
		( dwIpAddr == INADDR_NONE ) ||
		( ( dwIpAddr & dwMask ) != dwDest ) )
		return( FALSE );

	return( TRUE );
}

BOOL CProxyInfo::GetAutoProxyServer(LPSTR lpProxyHostName, LPDWORD lpdwProxyHostNameLength, LPSTR lpUrl, LPSTR lpHost)
{
	HMODULE hModJS;
	LPSTR lpszProxyHostName;

	// Declare and populate an AutoProxyHelperVtbl structure, and then 
	// place a pointer to it in a containing AutoProxyHelperFunctions 
	// structure, which will be passed to InternetInitializeAutoProxyDll:
	AutoProxyHelperVtbl Vtbl =
	{
		IsResolvable,
		GetIPAddress,
		ResolveHostName,
		IsInNet
	};
	AutoProxyHelperFunctions HelperFunctions = { &Vtbl };

	// Declare function pointers for the three autoproxy functions
	pfnInternetInitializeAutoProxyDll    pInternetInitializeAutoProxyDll;
	pfnInternetDeInitializeAutoProxyDll  pInternetDeInitializeAutoProxyDll;
	pfnInternetGetProxyInfo              pInternetGetProxyInfo;

	if( !( hModJS = LoadLibrary( "jsproxy.dll" ) ) )
		//throw CProxyInfo::Exception(GetLastError(), "Load jsproxy.dll Library error", __FILE__, __LINE__ );		
		return FALSE;

	if( !( pInternetInitializeAutoProxyDll = (pfnInternetInitializeAutoProxyDll)
		GetProcAddress( hModJS, "InternetInitializeAutoProxyDll" ) ) ||
		!( pInternetDeInitializeAutoProxyDll = (pfnInternetDeInitializeAutoProxyDll)
		GetProcAddress( hModJS, "InternetDeInitializeAutoProxyDll" ) ) ||
		!( pInternetGetProxyInfo = (pfnInternetGetProxyInfo)
		GetProcAddress( hModJS, "InternetGetProxyInfo" ) ) )
		//throw CProxyInfo::Exception(GetLastError(), "GetProcAddress", __FILE__, __LINE__ );		
		return FALSE;

	if( !pInternetInitializeAutoProxyDll( 0, m_cfile, NULL, &HelperFunctions, NULL ) )
		//throw CProxyInfo::Exception(GetLastError(), "InternetInitializeAutoProxyDll", __FILE__, __LINE__ );		
		return FALSE;

	if( !pInternetGetProxyInfo(lpUrl, sizeof(lpUrl), 
                              lpHost, sizeof(lpHost),
                              &lpszProxyHostName, lpdwProxyHostNameLength ) )
		//throw CProxyInfo::Exception(GetLastError(), "InternetGetProxyInfo", __FILE__, __LINE__ );		
		return FALSE;

	if( !pInternetDeInitializeAutoProxyDll( NULL, 0 ) )
		//throw CProxyInfo::Exception(GetLastError(), "InternetDeInitializeAutoProxyDll", __FILE__, __LINE__ );		
		return FALSE;

	strncpy(lpProxyHostName, lpszProxyHostName, *lpdwProxyHostNameLength);

	FreeLibrary(hModJS);
	return TRUE;
}

