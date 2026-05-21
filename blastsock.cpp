// blastsock.cpp: implementation of the blastsock class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "blastsock.h"
#include "neturoPassword.h"
#include <tlhelp32.h>

// -- for registry ------------------------------
//#include <atlbase.h> 


// For WinInet.h, WinHttp.h include together.
#include "WinINetDownLoader.h"

#undef BOOLAPI
#undef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#undef SECURITY_FLAG_IGNORE_CERT_CN_INVALID

#define URL_COMPONENTS URL_COMPONENTS_ANOTHER
#define URL_COMPONENTSA URL_COMPONENTSA_ANOTHER
#define URL_COMPONENTSW URL_COMPONENTSW_ANOTHER

#define LPURL_COMPONENTS LPURL_COMPONENTS_ANOTHER
#define LPURL_COMPONENTSA LPURL_COMPONENTS_ANOTHER
#define LPURL_COMPONENTSW LPURL_COMPONENTS_ANOTHER

#define INTERNET_SCHEME INTERNET_SCHEME_ANOTHER
#define LPINTERNET_SCHEME LPINTERNET_SCHEME_ANOTHER

#define HTTP_VERSION_INFO HTTP_VERSION_INFO_ANOTHER
#define LPHTTP_VERSION_INFO LPHTTP_VERSION_INFO_ANOTHER

#include <winhttp.h>

#undef URL_COMPONENTS
#undef URL_COMPONENTSA
#undef URL_COMPONENTSW

#undef LPURL_COMPONENTS
#undef LPURL_COMPONENTSA
#undef LPURL_COMPONENTSW

#undef INTERNET_SCHEME
#undef LPINTERNET_SCHEME

#undef HTTP_VERSION_INFO
#undef LPHTTP_VERSION_INFO


// 2008.06.20 - by min blastsock 최적화
//const int blastsock::CRYPTBUFFERSIZE = 2048;
const int blastsock::CRYPTBUFFERSIZE = 8192;


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

bool blastsock::StartLog(LPTSTR filename  , bool bEncrypt)
{
	if(filename == NULL)
		return false;
//	if(!kLog)
//		kLog = new BlastLog(); 
	return Socket::StartLog(filename , bEncrypt);
}

blastsock::blastsock() : ProxySocket()
{
	// Proxy Tunneling Variable
	m_tunnelingmode = BLASTSOCK_NO_PROXYTUNNELING;
//	m_pProxyinfo = NULL;
	m_proxyinfoown = false;
	m_pProxydata = NULL;
	m_proxydataLen = 0;
	
	// AES Crypt Variable
	m_cryptmode = BLASTSOCK_NO_CRYPT;
	m_pCryptlib = NULL;
	m_cryptown = false;
	m_pCryptqueue = NULL;
	m_lpSendCryptBuf = m_lpRecvCryptBuf = m_lpRecvCryptBuf2 = NULL;

	m_pSelectedProxyData = NULL;

	m_pSelectedProxyData = NULL;
	m_pSelectedProxyData = new CProxyData();

	m_proxytunnelingConnectOption = BLASTSOCK_PROXYTUNNELING_DIRECTCONNECT_FIRST;
}

blastsock::blastsock(blastsock* s) : ProxySocket()
{	// 일단은 암호화 정보만 넘기는 역할
	// 프록시 정보는 그냥 초기화 (귀찮어.ㅡ.ㅡ:)
	m_tunnelingmode = BLASTSOCK_NO_PROXYTUNNELING;
//	m_pProxyinfo = NULL;
	m_proxyinfoown = false;
	m_pProxydata = NULL;
	m_proxydataLen = 0;

	m_cryptmode = s->m_cryptmode;
	m_pCryptqueue = NULL;
	if(s->m_pCryptlib)
	{
		if(s->m_cryptown)
		{
			m_pCryptlib = new neturoCrypto;
			m_pCryptlib->SetAESiv(s->m_pCryptlib->GetHexEncodediv());
			m_pCryptlib->SetAESKey(s->m_pCryptlib->GetHexEncodedKey());
			m_cryptown = true;
		}
		else
		{
			m_pCryptlib = s->m_pCryptlib;
			m_cryptown = false;
		}
	}
	else
	{
		m_pCryptlib = NULL;
		m_cryptown = false;
	}
	m_lpSendCryptBuf = m_lpRecvCryptBuf = m_lpRecvCryptBuf2 = NULL;

	if(s->m_lpSendCryptBuf != NULL) m_lpSendCryptBuf = new CHAR[blastsock::CRYPTBUFFERSIZE];
	if(s->m_lpRecvCryptBuf != NULL) m_lpRecvCryptBuf = new CHAR[blastsock::CRYPTBUFFERSIZE];
	if(s->m_lpRecvCryptBuf2 != NULL) m_lpRecvCryptBuf2 = new CHAR[blastsock::CRYPTBUFFERSIZE];

	m_pSelectedProxyData = NULL;
	m_bManualProxy = FALSE;
	m_proxytunnelingConnectOption = s->m_proxytunnelingConnectOption;

	if(!kLog)
		kLog = new BlastLog(); 
}

blastsock::~blastsock()
{
	// Proxy Tunneling Variable
//	if(m_pProxyinfo && m_proxyinfoown) delete m_pProxyinfo;
	if(m_pProxydata) delete [] m_pProxydata;
	
	// AES Crypt Variable
	if(m_pCryptlib && m_cryptown) delete m_pCryptlib;
	if(m_pCryptqueue) delete m_pCryptqueue;
	if(m_lpSendCryptBuf) delete [] m_lpSendCryptBuf;
	if(m_lpRecvCryptBuf) delete [] m_lpRecvCryptBuf;
	if(m_lpRecvCryptBuf2) delete [] m_lpRecvCryptBuf2;

	if(m_pSelectedProxyData)
	{
		delete m_pSelectedProxyData;
		m_pSelectedProxyData = NULL;
	}

	if(kLog)
		delete kLog;
}

bool blastsock::WinInetConnect(char *strRetVal, int nRetValSize, char *strAgent, char *strServerAddr, int nServerPort, char *strUrl, HKEY hKeyParent, LPCSTR lpszKeyName)
{
	Socket::PrintLog(1 , "blastsock::WinInetConnect(strAgent:%s strServerAddr:%s nPort:%d strUrl:%s lpszKeyName:%s) Start\r\n", strAgent, strServerAddr, nServerPort, strUrl, lpszKeyName);
	WinINetDownLoader winInet;
	DWORD dwStatus;
	DWORD dwStatusSize = sizeof(dwStatus);
	DWORD dwRetValSize = nRetValSize;
	
	winInet.InternetOpen(strAgent);
	winInet.InternetConnect(strServerAddr, nServerPort);
	winInet.HttpOpenRequest(strUrl);
	winInet.HttpSendRequest();
	winInet.HttpQueryInfo(HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);
	
	if(dwStatus != 200)
	{
		Socket::PrintLog(1 , "blastsock::WinInetConnect() failed. Try ProxySocket::WinInetConnect(). error code:%d\r\n", dwStatus);
		CheckProxyEnvironment(hKeyParent, lpszKeyName);
		return ProxySocket::WinInetConnect(strRetVal, nRetValSize, strAgent, strServerAddr, nServerPort, strUrl);
	}
	else // 200 OK
	{
		winInet.InternetReadFile(strRetVal, dwRetValSize, &dwRetValSize);
		Socket::PrintLog(1 , "blastsock::WinInetConnect() 200 OK, retVal:%s\r\n", strRetVal);
	}
	
	return true;
}

bool blastsock::IsProxyEnv()
{
//	if(!m_pProxyinfo) return false;
//	if(m_pProxyinfo->GetProxyEnv() == PROXYENV_DIRECT || m_pProxyinfo->GetProxyEnv() == PROXYENV_UNKNOWN) return false;
	return true;
}

bool blastsock::CryptInit(int crypt, neturoCrypto* cryptlib, RSAKey* rsakey)
{
#ifdef NO_CRYPT
	return true; 
#endif
	m_cryptmode = crypt;

	if(m_cryptmode == BLASTSOCK_CRYPT_CREATEAESKEY ||
	   m_cryptmode == BLASTSOCK_CRYPT_RECVAESKEY ||
	   m_cryptmode == BLASTSOCK_CRYPT)
   {
		if(!m_pCryptlib && cryptlib == NULL) 
		{
			m_pCryptlib = new neturoCrypto;
			m_cryptown = true;
		}

		if(cryptlib) 
		{
			if(m_cryptown) delete m_pCryptlib;
			m_pCryptlib = cryptlib;
			m_cryptown = false;
		}

		// 버퍼초기화
		if(m_lpSendCryptBuf == NULL) m_lpSendCryptBuf = new CHAR[blastsock::CRYPTBUFFERSIZE];
		if(m_lpRecvCryptBuf == NULL) m_lpRecvCryptBuf = new CHAR[blastsock::CRYPTBUFFERSIZE];
		if(m_lpRecvCryptBuf2 == NULL) m_lpRecvCryptBuf2 = new CHAR[blastsock::CRYPTBUFFERSIZE];
   }

	// 암호화프로토콜
	switch(m_cryptmode)
	{
	case BLASTSOCK_CRYPT_CREATEAESKEY: 
	// 암호화키를 받아서 생성한 AES 키를 암호화하여 보낸다.
		Socket::PrintLog(0 , "CryptInit(BLASTSOCK_CRYPT_CREATEAESKEY)\r\n");
		return CryptCreateAESKey();
		break;
	case BLASTSOCK_CRYPT_RECVAESKEY: 
	// 받은 AES 키를 복호화키로 복호화하여 저장한다.
		Socket::PrintLog(0 , "CryptInit(BLASTSOCK_CRYPT_RECVAESKEY)\r\n");
		return CryptRecvAESKey(rsakey);
		break;
	case BLASTSOCK_CRYPT: 
	// 이미 AES 키를 가지고 있다. (AES 키를 가지고 있지 않은 경우 책임못짐-_-)
		Socket::PrintLog(0 , "CryptInit(BLASTSOCK_CRYPT)\r\n");
		return true;
		break;
	case BLASTSOCK_NO_CRYPT: 
	// 암호화 안한다. 할말없음.ㅋ
		Socket::PrintLog(0 , "CryptInit(BLASTSOCK_NO_CRYPT)\r\n");
		return true;
		break;
	default:
	// 파라미터 에러
		Socket::PrintLog(0 , "[Error]CryptInit(BLASTSOCK_ERROR_PARAMETER)\r\n");
		Socket::SetLastError(BLASTSOCK_ERROR_PARAMETER);
		return false;
	}
}

bool blastsock::CryptCreateAESKey()
{
	Socket::PrintLog(1 , "blastsock::CryptCreateAESKey() start\r\n");
	char rsa_public_key[321];
	char aes_secret_key[257];
	ZeroMemory(&rsa_public_key, sizeof(rsa_public_key));
	ZeroMemory(&aes_secret_key, sizeof(aes_secret_key));
	
	if(!Socket::RecvExact((char*)&rsa_public_key, sizeof(rsa_public_key)))
	{
		Socket::PrintLog(2 , "[Error] Fail to RecvExact(rsa_publick_key)\r\n");
		return false;
	}
	
	Socket::PrintLog(2 , "RecvExact(rsa_publick_key : %s)\r\n" , rsa_public_key);

	m_pCryptlib->InitAESKey();
				
	// Encrypt AES128 Key by RSA Public Key
	CryptoPP::byte KeyandIV[(AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) * 2+1];
	ZeroMemory(KeyandIV, (AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) * 2+1);
	memcpy(KeyandIV, m_pCryptlib->GetHexEncodedKey(), AES::DEFAULT_KEYLENGTH * 2);
	memcpy(KeyandIV + AES::DEFAULT_KEYLENGTH*2, m_pCryptlib->GetHexEncodediv(), AES::BLOCKSIZE*2);
	string EncryptedAESKey = m_pCryptlib->RSAEncryptString(rsa_public_key, (const char *)KeyandIV);
	if(EncryptedAESKey.length() == 0) return false;
	memcpy(aes_secret_key, EncryptedAESKey.c_str(), 256);

	if(!Socket::SendExact((char*)&aes_secret_key, sizeof(aes_secret_key))) 
	{
		Socket::PrintLog(2 , "[Error] Fail to SendExact(aes_secret_key)\r\n");
		return false;
	}

	Socket::PrintLog(2 , "SendExact(aes_secret_key : %s)\r\n" , aes_secret_key);
	Socket::PrintLog(1 , "blastsock::CryptCreateAESKey() End\r\n");
	
	return true;
}

bool blastsock::CryptRecvAESKey(RSAKey* rsakey)
{
	Socket::PrintLog(1 , "blastsock::CryptRecvAESKey() Start\r\n");
	char pvk[1300];
	char pbk[321];
	char rsa_public_key[321];
	char aes_secret_key[257];

	ZeroMemory(pvk, sizeof(pvk));
	ZeroMemory(pbk, sizeof(pbk));
	ZeroMemory(&rsa_public_key, sizeof(rsa_public_key));
	ZeroMemory(&aes_secret_key, sizeof(aes_secret_key));
	
	// Initialize RSA Private & Public Key - by scyrie
	if(rsakey) 
	{	// RSA 키가 있으면 그걸로 대체하고
		memcpy(pvk, rsakey->pvk, 1300);
		memcpy(pbk, rsakey->pbk, 321);
	}
	else
	{	// 없으면 새로 만들어서 쓴다
		m_pCryptlib->GenerateRSAKey(1024, pvk, pbk);
	}
	
	// Key Exchange by scyrie
	memcpy(rsa_public_key, pbk, 320);
	if(!Socket::SendExact((LPSTR)&rsa_public_key, sizeof(rsa_public_key))) 
	{
		Socket::PrintLog(2 , "[Error] Fail to SendExact(rsa_public_key)\r\n");
		return false;
	}

	Socket::PrintLog(2 , "SendExact(rsa_public_key : %s)\r\n" , rsa_public_key);

	if(!Socket::RecvExact((LPSTR)&aes_secret_key, sizeof(aes_secret_key)))
	{
		Socket::PrintLog(2 , "[Error] Fail to RecvExact(aes_secret_key)\r\n");
		return false;
	}

	Socket::PrintLog(2 , "RecvExact(aes_secret_key : %s)\r\n" , aes_secret_key);
	
	// Decrypt Key & IV and Seperate them.
	CryptoPP::byte KeyandIV[(AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) *2 +1];
	ZeroMemory(KeyandIV, (AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) *2 +1);

	memcpy(KeyandIV, (m_pCryptlib->RSADecryptString(pvk, aes_secret_key)).c_str(), (AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) * 2 + 1);
	
	m_pCryptlib->SetAESKey(KeyandIV);
	m_pCryptlib->SetAESiv(KeyandIV + AES::DEFAULT_KEYLENGTH*2);
	
	Socket::PrintLog(1 , "blastsock::CryptRecvAESKey() End\r\n" );
	return TRUE;
}

//bool blastsock::TunnelingInit(unsigned int tunneling, CProxyInfo* pProxyInfo, bool fromIE, bool regsave, bool cfileown, HKEY hKeyParent, LPCSTR lpszKeyName)
bool blastsock::TunnelingInit(unsigned int tunneling, void* pProxyInfo, bool fromIE, bool regsave, bool cfileown, HKEY hKeyParent, LPCSTR lpszKeyName)
{
	Socket::PrintLog(1 , "blastsock::TunnelingInit(tunneling(%d) , fromIE(%d) , regsave(%d) , cfileown(%d) , lpszKeyName(%s) start\r\n",
		tunneling , fromIE , regsave , cfileown , lpszKeyName);

	m_tunnelingmode = tunneling;
	if(m_tunnelingmode == BLASTSOCK_PROXYTUNNELING || m_tunnelingmode == BLASTSOCK_PROXYQUERY)
	{
		//registry를 읽어서 암호 / 비밀번호를 확인 한다.
		CheckProxyEnvironment(hKeyParent, lpszKeyName);
		
	
	
/*
		if(!m_pProxyinfo && pProxyInfo == NULL) 
		{
			m_pProxyinfo = new CProxyInfo;
			m_proxyinfoown = true;
		}

		if(pProxyInfo) 
		{
			if(m_proxyinfoown) delete m_pProxyinfo;
			m_pProxyinfo = pProxyInfo;
			m_proxyinfoown = false;
		}

		if(fromIE)
		{
			m_pProxyinfo->LoadProxyEnvFromExplorer(cfileown);
		}
		else
		{
			m_pProxyinfo->LoadProxyEnv(hKeyParent, lpszKeyName, cfileown);	
		}

		if(regsave)
		{
			m_pProxyinfo->SaveProxyEnv(hKeyParent, lpszKeyName);
		}
		
		m_bManualProxy = CheckManualProxy(hKeyParent, lpszKeyName);
		
		if(m_bManualProxy == TRUE) 
		{
			m_tunnelingmode = BLASTSOCK_PROXYTUNNELING_MANUAL;
		}
		*/

	}
	Socket::PrintLog(1 , "blastsock::TunnelingInit(m_tunnelingmode = %d) End\r\n" , m_tunnelingmode);
	return true;
}

void blastsock::CheckProxyEnvironment(HKEY hKeyParent, LPCSTR lpszKeyName)
{
	if(IsWinXPorLater()) 
	{
		HANDLE hToken = GetToken();
		
		Socket::PrintLog(1 , "blastsock::GetToken() = 0x%x\r\n",hToken);
		
		BOOL ret = ImpersonateLoggedOnUser(hToken);
		Socket::PrintLog(1 , "blastsock::ImpersonateLoggedOnUser() = %d\r\n" , ret);
	}	

	CheckManualProxy(hKeyParent, lpszKeyName);
	FindProxyFromWinHttp();

	if(IsWinXPorLater()) 
	{
		RevertToSelf();
	}
}

bool blastsock::CheckManualProxy(HKEY hKeyParent, LPCSTR lpszKeyName)
{
	Socket::PrintLog(2 , "Start CProxyInfo::CheckManualProxy(lpszKeyName : %s)\r\n" , lpszKeyName);

	HKEY key;
	DWORD dwDisp		     = 0;
	DWORD temp_size		     = MAX_ID_LEN;
	DWORD temp_size_password = MAXPWLEN;
	DWORD temp_size_ip		 = 16;
	DWORD temp_size_port	 = 6;
	char temp_id[MAX_ID_LEN+1];
	char temp_password[MAXPWLEN+1];
	char temp_ip[16];
	char temp_port[6];
	char temp_reg[255];
	long ret;
	
	ZeroMemory(temp_id, MAX_ID_LEN+1);
	ZeroMemory(temp_password, MAXPWLEN+1);
	ZeroMemory(temp_ip, 16);
	ZeroMemory(temp_port, 6);
	ZeroMemory(temp_reg, 255);
	
	//LoadString(g_hRes, IDS_REG_HKEY_LOCAL_MACH, temp_reg, 255);
	if(lpszKeyName == NULL) 
	{
#ifdef ANYSUPPORT
#ifdef LINKVNC
		strcpy(temp_reg, "Software\\linkvnc");
#elif LINKEIGHT
		strcpy(temp_reg, "Software\\LinkMeMine\\LinkEight");
#else
		strcpy(temp_reg, "Software\\Koino\\AnySupport");
#endif // LINKVNC
#else
		strcpy(temp_reg, "Software\\LinkMeMine\\Manager");
#endif // ANYSUPPORT
	}
	else 
		strcpy(temp_reg, lpszKeyName);

	//RegCreateKeyEx(HKEY_LOCAL_MACHINE, temp_reg, 0, NULL,
	//	REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key,&dwDisp);


	ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE, temp_reg, 0, NULL,
		REG_OPTION_NON_VOLATILE, KEY_READ, NULL, &key,&dwDisp);
	
	DWORD dwUseProxy = 0;
	DWORD type_dw = REG_DWORD;
	DWORD size_dw = sizeof(DWORD);

	m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);

	ret = RegQueryValueEx(key, "UseProxy", NULL, &type_dw, (LPBYTE)&dwUseProxy, &size_dw);	
	if(ret == ERROR_SUCCESS)
	{
		if((BOOL)dwUseProxy == FALSE) 
		{
			Socket::PrintLog(3 , "UseProxy(%d)\r\n" , dwUseProxy);
			Socket::PrintLog(2 , "End CProxyInfo::CheckManualProxy \r\n");
		
			//return FALSE;
		}
	}
	else 
	{
		Socket::PrintLog(3 , "Fail RegQueryValueEx(key, UseProxy\r\n");
		Socket::PrintLog(2 , "End CProxyInfo::CheckManualProxy \r\n");
	
		//return FALSE;
	}
	ret = RegQueryValueEx(key, "ProxyID", 0, NULL,  (unsigned char*)temp_id, &temp_size);
	if(ret == ERROR_SUCCESS)
	{
		RegQueryValueEx(key, "ProxyID", 0, NULL,  (unsigned char*)temp_id, &temp_size);
		m_pSelectedProxyData->SetUser(temp_id);	

		Socket::PrintLog(1 , "blastsock::CheckManualProxy(GetProxyAuthID : %s)\r\n" , temp_id);
	}
	else
	{
		RegSetValueEx(key, "ProxyID", 0, REG_SZ, (const unsigned char*)"", 1);
		m_pSelectedProxyData->SetUser("");
	}
	
	DWORD type_bi_password   = REG_BINARY;
	ret = RegQueryValueEx(key, "ProxyPW", NULL, &type_bi_password,  (LPBYTE)temp_password, &temp_size_password);
	if(ret == ERROR_SUCCESS)
	{
		RegQueryValueEx(key, "ProxyPW", NULL, &type_bi_password,  (LPBYTE)temp_password, &temp_size_password);
		neturoPassword::ToText plain(temp_password);
		memcpy(temp_password, plain, 13);
		m_pSelectedProxyData->SetPass(temp_password);

		Socket::PrintLog(1 , "blastsock::CheckManualProxy(GetProxyAuthPW : %s)\r\n" , temp_password);
	}
	else
	{
		RegDeleteValue(key, "ProxyPW");
		m_pSelectedProxyData->SetPass("");
		Socket::PrintLog(1 , "blastsock::CheckManualProxy(GetProxyAuthPW FAIL)  \r\n");
	}
	
	if(temp_id!=NULL && strlen(temp_id)>0 && temp_password!=NULL && strlen(temp_password)>0) 
	{
		Socket::PrintLog(1 , "Auto Mode, id:%s, pw:%s\r\n" , temp_id, temp_password);
		m_pSelectedProxyData->SetAuth(TRUE);
	}
	DWORD dwProxyAuto = 0;
	ret = RegQueryValueEx(key, "ProxyAuto", NULL, &type_dw, (LPBYTE)&dwProxyAuto, &size_dw);	
	if(ret == ERROR_SUCCESS)
	{
		if((BOOL)dwProxyAuto == TRUE) 
		{
			Socket::PrintLog(3 , "ProxyAuto(%d)\r\n" , dwProxyAuto);
			Socket::PrintLog(2 , "End CProxyInfo::CheckManualProxy \r\n");
		
			//return FALSE;
		}
	}
	else 
	{
		Socket::PrintLog(3 , "Fail RegQueryValueEx(key, ProxyAuto\r\n");
		Socket::PrintLog(2 , "End CProxyInfo::CheckManualProxy \r\n");
	
		//return FALSE;
	}
	

	ret = RegQueryValueEx(key, "ProxyIP", 0, NULL,  (unsigned char*)temp_ip, &temp_size_ip);

	if(ret == ERROR_SUCCESS)
	{
		RegQueryValueEx(key, "ProxyIP", 0, NULL,  (unsigned char*)temp_ip, &temp_size_ip);
		m_pSelectedProxyData->SetProxyHost(temp_ip);
	}
	else
	{
		Socket::PrintLog(3 , "Fail RegQueryValueEx(key, ProxyIP\r\n");
		Socket::PrintLog(2 , "End CProxyInfo::CheckManualProxy \r\n");
	
		return FALSE;
	}

	int nProxyPort = 0;
	ret = RegQueryValueEx(key, "ProxyPort", 0, NULL,  (unsigned char*)temp_port, &temp_size_port);
	if(ret == ERROR_SUCCESS) 
	{
		RegQueryValueEx(key, "ProxyPort", 0, NULL,  (unsigned char*)temp_port, &temp_size_port);
		nProxyPort = atoi(temp_port);	
		m_pSelectedProxyData->SetProxyPort((SHORT)nProxyPort);
	}
	else
	{
		Socket::PrintLog(3 , "Fail RegQueryValueEx(key, ProxyPor\r\n");
		Socket::PrintLog(2 , "End CProxyInfo::CheckManualProxy \r\n");
	
		return FALSE;
	}
	
	RegCloseKey(key);
	
	m_pSelectedProxyData->SetType(PROXYTYPE_HTTP11); //2010.04.06 wsj

	Socket::PrintLog(2 , "m_pSelectedProxyData->SetType(PROXYTYPE_HTTP11)\r\n");
	Socket::PrintLog(2 , "End CProxyInfo::CheckManualProxy(%s , %d)\r\n" ,m_pSelectedProxyData->GetProxyHost() , m_pSelectedProxyData->GetProxyPort());

	return TRUE;
}

bool blastsock::Connect(const char* addr, unsigned int port)
{
	Socket::PrintLog(1 , "blastsock::Connect(%s : %d) Start\r\n" , addr , port);

	int i;

	switch(m_tunnelingmode)
	{
	case BLASTSOCK_PROXYTUNNELING_MANUAL:
		{

				/* destination port 가 443 이라면 proxy 환경이더라도 
		   direct 로 열어 놓았을 가능성이 높으므로 일단 바로 접속을 해본다 */
			//if(m_pProxyinfo->GetProxyEnv() == PROXYENV_UNKNOWN || m_pProxyinfo->GetProxyEnv() == PROXYENV_DIRECT)
			Socket::PrintLog(2 , "m_tunnelingmode == BLASTSOCK_PROXYTUNNELING_MANUAL \r\n");

			//if(port == 443 || port == 80)
			{
				Socket::PrintLog(2 , "Try to connect directly(%s : %d)\r\n" , addr , port);
				//if(Socket::Connect(addr, port)) 
				if(Socket::Connect(addr, port , false /* non-blocking */))
				{
					Socket::PrintLog(2 , "Success connect to destination directly(%s : %d)\r\n" , addr , port);
					Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
				
					return true;
				}
				else
				{
					Socket::PrintLog(2 , "Fail to connect direct(%s : %d), GetLastError:%d\r\n" , addr , port, Socket::GetLastError());
				}
				/* Non-Blocking Mode로 Connect를 시도 후 소켓을 닫고 , 다시 생성 한다 */
				CloseSocket();
				Create();
				/* */
			}

			BOOL bFind = FALSE;
			
//			m_pProxyinfo->InitProxyServerData(addr, addr, &m_pProxydata, m_proxydataLen);
			
			Socket::PrintLog(2 , "InitProxyServerData()\r\n" );
				

			for(i = 0; i < m_proxydataLen; i++)
			{
				if(m_pProxydata[i].GetType() == PROXYTYPE_NOPROXY) 
				{
					continue;
				}

				if(!strcmp(m_pSelectedProxyData->GetProxyHost() , m_pProxydata[i].GetProxyHost()) && m_pSelectedProxyData->GetProxyPort() == m_pProxydata[i].GetProxyPort())
				{
//					memcpy(&m_ProxyData, m_pSelectedProxyData, sizeof(m_ProxyData));
 					m_ProxyData = m_pProxydata[i];
 					m_ProxyData.SetUser(m_pSelectedProxyData->GetUser());
 					m_ProxyData.SetPass(m_pSelectedProxyData->GetPass());
					m_ProxyData.SetAuth(TRUE);
					bFind = TRUE;
					Socket::PrintLog(2 , "Success to Find Proxy! Type(%d) , SetUser(%s) , SetPass(%s)\r\n" ,  m_ProxyData.GetType(), m_ProxyData.GetUser(), m_ProxyData.GetPass() );
					break;
				}
			}

			memcpy(&m_ProxyData, m_pSelectedProxyData, sizeof(m_ProxyData));
			//m_ProxyData = m_pSelectedProxyData;
			m_ProxyData.SetUser(m_pSelectedProxyData->GetUser());
			m_ProxyData.SetPass(m_pSelectedProxyData->GetPass());
			m_ProxyData.SetAuth(FALSE);
			m_ProxyData.SetType(PROXYTYPE_HTTP11);
			bFind = TRUE;


			if(bFind == FALSE) 
			{
				Socket::PrintLog(1 , "Fail to Find Proxy! blastsock::Connect() End\r\n");
				return false;
			}

			if(ProxySocket::Connect(addr, port))
			{	// connection established
				Socket::PrintLog(2 , "Success ProxySocket::Connect(%s , %d)\r\n" , addr , port);
				break;
			}
			else
			{	// connection failed
				/* Non-Blocking Mode로 Connect를 시도 후 소켓을 닫고 , 다시 생성 한다 */
				CloseSocket();
				Create();

				if(m_ProxyData.GetType() == PROXYTYPE_SOCKS4 && WSAGetLastError() != PROXYSOCKET_ERROR_NOCONN)
				{
					Socket::PrintLog(2 , "[Fail] ProxySocket::Connect(%s , %d)\r\n" , addr , port);
					Socket::PrintLog(2 , "Change ProxyType to PROXYTYPE_SOCKS5 \r\n");
									
					m_ProxyData.SetType(PROXYTYPE_SOCKS5);
					if(ProxySocket::Connect(addr, port)) 
					{
						Socket::PrintLog(2 , "Success ProxySocket::Connect(%s , %d)\r\n" , addr , port);
						break;
					}
					else
					{
						Socket::PrintLog(2 , "[Fail] ProxySocket::Connect(%s , %d)\r\n" , addr , port);
					}
				}
			}
		}
		break;
	case BLASTSOCK_PROXYQUERY: 
	case BLASTSOCK_PROXYTUNNELING: 
		Socket::PrintLog(2 , "m_tunnelingmode == BLASTSOCK_PROXYQUERY ||  BLASTSOCK_PROXYTUNNELING (%d)\r\n" , m_tunnelingmode);

		// 20170725 [프록시 접속 속도 개선] FIXME : 설명 필요
		if(m_proxytunnelingConnectOption == BLASTSOCK_PROXYTUNNELING_DIRECTCONNECT_FIRST) {
			// 테스트
			CloseSocket();
			Create();
			/***/
			if(!ConnectDirect(addr, port)) {
				/* Non-Blocking Mode로 Connect를 시도 후 소켓을 닫고 , 다시 생성 한다 */
				CloseSocket();
				Create();
				/* */
				
				if(!ConnectProxy(addr, port)) {
					CloseSocket();
					return false;
				}
			}
		} else {
			// 테스트
			CloseSocket();
			Create();
			/***/
			if(!ConnectProxy(addr, port)) {
				/* Non-Blocking Mode로 Connect를 시도 후 소켓을 닫고 , 다시 생성 한다 */
				CloseSocket();
				Create();
				/* */
				
				if(!ConnectDirect(addr, port)) {
					CloseSocket();
					return false;
				}
			}
		}

#if 0 // 20170725 [프록시 접속 속도 개선]
		/* destination port 가 443 이라면 proxy 환경이더라도 
		   direct 로 열어 놓았을 가능성이 높으므로 일단 바로 접속을 해본다 */
		//if(m_pProxyinfo->GetProxyEnv() == PROXYENV_UNKNOWN || m_pProxyinfo->GetProxyEnv() == PROXYENV_DIRECT)
		//if(port == 443 || port == 80) 
		//port scanning으로 서버외에는 P2P 연결 시 80 , 443을 사용하지 않는다.
		//항상 direct로 연결을 시도 해 본다.
		{

			Socket::PrintLog(2 , "Try to connect directly(%s : %d)\r\n" , addr , port);

			//if(Socket::Connect(addr, port)) 
			if(Socket::Connect(addr, port , false /* non-blocking */)) 
			{
				Socket::PrintLog(2 , "Success connect to destination directly(%s : %d)\r\n" , addr , port);
				Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
			
				return true;
			}
			else
			{
				Socket::PrintLog(2 , "Fail to connect direct(%s : %d), GetLastError:%d\r\n" , addr , port, Socket::GetLastError());
			}

			/* Non-Blocking Mode로 Connect를 시도 후 소켓을 닫고 , 다시 생성 한다 */
			CloseSocket();
			Create();
			/* */
		}


		if(m_ProxyData.GetType() == PROXYTYPE_NOPROXY)
			return false;

		Socket::PrintLog(2 , "try  ProxySocket::Connect(%s , %d)\r\n" , addr , port);
		if(ProxySocket::Connect(addr, port))
		{
			Socket::PrintLog(2 , "Success ProxySocket::Connect(%s , %d)\r\n" , addr , port);
			return true;
		}
		else
		{	// connection failed
			
			/* Non-Blocking Mode로 Connect를 시도 후 소켓을 닫고 , 다시 생성 한다 */
			CloseSocket();
			Create();
			
			if(m_ProxyData.GetType() == PROXYTYPE_SOCKS4 && WSAGetLastError() != PROXYSOCKET_ERROR_NOCONN)
			{
				Socket::PrintLog(2 , "[Fail] ProxySocket::Connect(%s , %d)\r\n" , addr , port);
				Socket::PrintLog(2 , "Change ProxyType to PROXYTYPE_SOCKS5 \r\n");
				
				m_ProxyData.SetType(PROXYTYPE_SOCKS5);
				if(ProxySocket::Connect(addr, port)) 
				{
					Socket::PrintLog(2 , "Success ProxySocket::Connect(%s , %d)\r\n" , addr , port);
					return true;
				}
				else
				{
					Socket::PrintLog(2 , "[Fail] ProxySocket::Connect(%s , %d)\r\n" , addr , port);
					return false;
				}
			}
		}
		return false;
#endif

		
#if 0 // old
		// 프록시 서버의 정보를 구한다
//		m_pProxyinfo->InitProxyServerData(addr, addr, &m_pProxydata, m_proxydataLen);
		
		Socket::PrintLog(2 , "InitProxyServerData()\r\n" );
		
		/* m_pProxyData 에 있는 정보로 될 때까지 순서대로 접속해본다 */
		for(i = 0; i < m_proxydataLen; i++)
		{
			m_ProxyData = m_pProxydata[i];	
			/* destination port 가 443 이라면 위에서 direct 접속을 해봤으니까
			   여기서 할 필요가 없다. */
			//if((port== 80 || port == 443) && m_ProxyData.GetType() == PROXYTYPE_NOPROXY) 
			//port scanning으로 서버외에는 P2P 연결 시 80 , 443을 사용하지 않는다.
			//항상 direct로 연결을 시도 해 본다.
			if( m_ProxyData.GetType() == PROXYTYPE_NOPROXY) 
			{
				continue;
			}

			/* HTTP proxy인 경우 GET(query), CONNECT(tunneling) 두가지 방식이
			   있다. GET 을 위해서 proxy type 을 바꿔준다 */
			if(m_tunnelingmode == BLASTSOCK_PROXYQUERY && m_ProxyData.GetType() == PROXYTYPE_HTTP11)
			{	// HTTP Query mode
				m_ProxyData.SetType(PROXYTYPE_HTTP11QUERY);
			}

			if(m_pSelectedProxyData != NULL)
			{
				m_ProxyData.SetUser(m_pSelectedProxyData->GetUser());
 				m_ProxyData.SetPass(m_pSelectedProxyData->GetPass());
				m_ProxyData.SetAuth(TRUE);
				Socket::PrintLog(2 , "Success to Find Proxy! Type(%d) , SetUser(%s) , SetPass(%s)\r\n" ,  m_ProxyData.GetType(), m_ProxyData.GetUser(), m_ProxyData.GetPass() );
			}	
			
			if(ProxySocket::Connect(addr, port))
			{
				Socket::PrintLog(2 , "Success ProxySocket::Connect(%s , %d)\r\n" , addr , port);
				break;
			}
			else
			{	// connection failed
				
				/* Non-Blocking Mode로 Connect를 시도 후 소켓을 닫고 , 다시 생성 한다 */
				CloseSocket();
				Create();

				if(m_ProxyData.GetType() == PROXYTYPE_SOCKS4 && WSAGetLastError() != PROXYSOCKET_ERROR_NOCONN)
				{
					Socket::PrintLog(2 , "[Fail] ProxySocket::Connect(%s , %d)\r\n" , addr , port);
					Socket::PrintLog(2 , "Change ProxyType to PROXYTYPE_SOCKS5 \r\n");
				
					m_ProxyData.SetType(PROXYTYPE_SOCKS5);
					if(ProxySocket::Connect(addr, port)) 
					{
						Socket::PrintLog(2 , "Success ProxySocket::Connect(%s , %d)\r\n" , addr , port);
						break;
					}
					else
					{
						Socket::PrintLog(2 , "[Fail] ProxySocket::Connect(%s , %d)\r\n" , addr , port);
					}
				}
			}
		}
		if(i == m_proxydataLen) return false;
#endif
		break;
	case BLASTSOCK_NO_PROXYTUNNELING: 
		Socket::PrintLog(2 , "m_tunnelingmode == BLASTSOCK_NO_PROXYTUNNELING \r\n");
		//if(!Socket::Connect(addr, port))
		if(!Socket::Connect(addr, port , false /* non-blocking */))
		{
			Socket::PrintLog(2 , "[Fail] Socket::Connect(%s , %d)\r\n" , addr , port);
			Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
		
			return false;
		}
		Socket::PrintLog(2 , "Success Socket::Connect(%s , %d)\r\n" , addr , port);
		break;
	default: 
		Socket::PrintLog(2 , "[Error] BLASTSOCK_ERROR_PARAMETER \r\n");
		Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
	
		Socket::SetLastError(BLASTSOCK_ERROR_PARAMETER);
		
		return false;
	}

	Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
	return true;
}

bool blastsock::ConnectDirect(const char* addr, unsigned int port)
{
	Socket::PrintLog(2 , "Try to connect directly(%s : %d)\r\n" , addr , port);
	
	//if(Socket::Connect(addr, port)) 
	if(Socket::Connect(addr, port , false /* non-blocking */)) 
	{
		Socket::PrintLog(2 , "Success connect to destination directly(%s : %d)\r\n" , addr , port);
		Socket::PrintLog(1 , "blastsock::Connect() End\r\n");
		
		m_proxytunnelingConnectOption = BLASTSOCK_PROXYTUNNELING_DIRECTCONNECT_FIRST;

		return true;
	}
	else
	{
		Socket::PrintLog(2 , "Fail to connect direct(%s : %d), GetLastError:%d\r\n" , addr , port, Socket::GetLastError());
	}
	
	return false;
}
	
bool blastsock::ConnectProxy(const char* addr, unsigned int port)
{
	if(m_ProxyData.GetType() == PROXYTYPE_NOPROXY)
		return false;
	
	Socket::PrintLog(2 , "try  ProxySocket::Connect(%s , %d)\r\n" , addr , port);
	if(ProxySocket::Connect(addr, port))
	{
		Socket::PrintLog(2 , "Success ProxySocket::Connect(%s , %d)\r\n" , addr , port);
		m_proxytunnelingConnectOption = BLASTSOCK_PROXYTUNNELING_PROXYCONNECT_FIRST;
		return true;
	}
	else
	{	// connection failed
		
		/* Non-Blocking Mode로 Connect를 시도 후 소켓을 닫고 , 다시 생성 한다 */
		CloseSocket();
		Create();
		
		if(m_ProxyData.GetType() == PROXYTYPE_SOCKS4 && WSAGetLastError() != PROXYSOCKET_ERROR_NOCONN)
		{
			Socket::PrintLog(2 , "[Fail] ProxySocket::Connect(%s , %d)\r\n" , addr , port);
			Socket::PrintLog(2 , "Change ProxyType to PROXYTYPE_SOCKS5 \r\n");
			
			m_ProxyData.SetType(PROXYTYPE_SOCKS5);
			if(ProxySocket::Connect(addr, port)) 
			{
				Socket::PrintLog(2 , "Success ProxySocket::Connect(%s , %d)\r\n" , addr , port);
				return true;
			}
			else
			{
				Socket::PrintLog(2 , "[Fail] ProxySocket::Connect(%s , %d)\r\n" , addr , port);
				return false;
			}
		}
	}
	return false;
}

/*bool blastsock::SendExact(const char* buf, unsigned int bufLen, unsigned int usebuf)
{
	// 암호화하지 않을 경우
	if(m_cryptmode == BLASTSOCK_NO_CRYPT) return Socket::SendExact(buf, bufLen);

	// 버퍼사용하는 경우 패킷의 길이를 먼저 보낸다
	if(usebuf == BLASTSOCK_BUFFER) 
	{	
		if(!Socket::SendExact((char*)&bufLen, sizeof(unsigned int))) return false;
	}

	// 암호화해서 보낸다
	if(bufLen <= blastsock::CRYPTBUFFERSIZE)
	{
		m_pCryptlib->AESEncryptString(m_lpSendCryptBuf, buf, bufLen);
		return Socket::SendExact(m_lpSendCryptBuf, bufLen);
	}
	else
	{
		char* cryptbuf = new char[bufLen+1];
		m_pCryptlib->AESEncryptString(cryptbuf, buf, bufLen);
		bool result = Socket::SendExact(cryptbuf, bufLen);
		delete [] cryptbuf;
		return result;
	}
}*/

// 2008.06.20 - by min blastsock 최적화
// data 길이를 같이 보내 Socket IO를 최소화 한다.
bool blastsock::SendExact(const char* buf, unsigned int bufLen, unsigned int usebuf)
{
	// 암호화하지 않을 경우
	if(m_cryptmode == BLASTSOCK_NO_CRYPT) return Socket::SendExact(buf, bufLen);

	// 버퍼사용하는 경우 패킷의 길이를 먼저 보낸다
	if(usebuf == BLASTSOCK_BUFFER) 
	{	
		char * buff;
		buff = new char[bufLen+sizeof(unsigned int)+1];
		memcpy(buff, (char*)&bufLen, sizeof(unsigned int));
		
		if(bufLen <= blastsock::CRYPTBUFFERSIZE)
		{
			m_pCryptlib->AESEncryptString(m_lpSendCryptBuf, buf, bufLen);
			memcpy(buff+sizeof(unsigned int), m_lpSendCryptBuf, bufLen);

		}
		else
		{
			char* cryptbuf = new char[bufLen+1];
			m_pCryptlib->AESEncryptString(cryptbuf, buf, bufLen);
			memcpy(buff+sizeof(unsigned int), cryptbuf, bufLen);
			delete [] cryptbuf;
		}
	
		bool result =  Socket::SendExact(buff, bufLen+sizeof(unsigned int));
		
		delete [] buff;
		return result;

	}
	else{
		// 암호화해서 보낸다
		if(bufLen <= blastsock::CRYPTBUFFERSIZE)
		{
			m_pCryptlib->AESEncryptString(m_lpSendCryptBuf, buf, bufLen);
			return Socket::SendExact(m_lpSendCryptBuf, bufLen);
		}
		else
		{
			char* cryptbuf = new char[bufLen+1];
			m_pCryptlib->AESEncryptString(cryptbuf, buf, bufLen);
			bool result = Socket::SendExact(cryptbuf, bufLen);
			delete [] cryptbuf;
			return result;
		}
	}
}


bool blastsock::RecvExact(char* buf, unsigned int bufLen, unsigned int usebuf, int flags)
{
	// 암호화하지 않을 경우
	if(m_cryptmode == BLASTSOCK_NO_CRYPT) return Socket::RecvExact(buf, bufLen, flags);

	// 버퍼사용X
	if(usebuf == BLASTSOCK_NO_BUFFER)
	{
		// 멤버 변수 버퍼 사용
		if(bufLen <= blastsock::CRYPTBUFFERSIZE)
		{
			if(!Socket::RecvExact(m_lpRecvCryptBuf, bufLen)) return false;
			m_pCryptlib->AESDecryptString(buf, m_lpRecvCryptBuf, bufLen);	
		}
		// 힙 공간에 버퍼 생성하여 사용
		else
		{
			char* cryptbuf = new char[bufLen+1];
			if(!Socket::RecvExact(cryptbuf, bufLen))
			{
				delete [] cryptbuf;
				return false;
			}
			m_pCryptlib->AESDecryptString(buf, cryptbuf, bufLen);	
			delete [] cryptbuf;
		}
		return true;
	}

	if(!m_pCryptqueue) m_pCryptqueue = new StringQueue();

	unsigned int iTotalBufferBytesRecv;
	while(bufLen > m_pCryptqueue->GetSize())
	{	// 받을 용량보다 버퍼의 내용이 적다면 더 받아서 버퍼에 저장한다
		if(!Socket::RecvExact((char*)&iTotalBufferBytesRecv, sizeof(unsigned int))) return false;

		// 멤버 변수 버퍼 사용
		if(iTotalBufferBytesRecv <= blastsock::CRYPTBUFFERSIZE)	
		{
			if(!Socket::RecvExact(m_lpRecvCryptBuf, iTotalBufferBytesRecv)) return false;
			m_pCryptlib->AESDecryptString(m_lpRecvCryptBuf2, m_lpRecvCryptBuf, iTotalBufferBytesRecv);	
			while(!m_pCryptqueue->Enqueue(m_lpRecvCryptBuf2, iTotalBufferBytesRecv))
			{
				// Buffer Overflow
				// 사이즈가 두배인 큐를 새로 생성한다
				StringQueue* _pCryptqueue = new StringQueue(m_pCryptqueue->GetMaxSize()*2);
				*_pCryptqueue = *m_pCryptqueue;
				delete m_pCryptqueue;
				m_pCryptqueue = _pCryptqueue;
			}
		}
		// 힙 공간에 버퍼 생성하여 사용
		else
		{
			char* cryptbuf = new char[iTotalBufferBytesRecv+1];
			if(!Socket::RecvExact(cryptbuf, iTotalBufferBytesRecv))
			{
				delete [] cryptbuf;
				return false;
			}
			char* cryptbuf2 = new char[iTotalBufferBytesRecv+1];
			m_pCryptlib->AESDecryptString(cryptbuf2, cryptbuf, iTotalBufferBytesRecv);	
			while(!m_pCryptqueue->Enqueue(cryptbuf2, iTotalBufferBytesRecv)) 
			{
				// Buffer Overflow
				// 사이즈가 두배인 큐를 새로 생성한다
				StringQueue* _pCryptqueue = new StringQueue(m_pCryptqueue->GetMaxSize()*2);
				*_pCryptqueue = *m_pCryptqueue;
				delete m_pCryptqueue;
				m_pCryptqueue = _pCryptqueue;
			}
			delete [] cryptbuf;
			delete [] cryptbuf2;
		}
	}
	
	if(!m_pCryptqueue->Dequeue(buf, bufLen, flags)) 
	{
		WSASetLastError(BLASTSOCK_ERROR_CRYPTBUFFEREMPTY);
		return false;
	}

	return true;
}

bool blastsock::FindProxyFromWinHttp()
{
	Socket::PrintLog(1 , "Start blastsock::FindProxyFromWinHttp\r\n");

	HINTERNET hHttpSession = NULL;
	HINTERNET hConnect     = NULL;
	HINTERNET hRequest     = NULL;
	
	WINHTTP_AUTOPROXY_OPTIONS  AutoProxyOptions;
	WINHTTP_PROXY_INFO         ProxyInfo;
	DWORD                      cbProxyInfoSize = sizeof(ProxyInfo);
	
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieProxyConfig = { 0 };
	ZeroMemory( &AutoProxyOptions, sizeof(AutoProxyOptions) );
	ZeroMemory( &ProxyInfo, sizeof(ProxyInfo) );
	
	// 20170810 : proxy bypass가 512를 넘는 경우가 있어 1024로 버퍼 길이를 늘린다.
	//char logbuf[512];
	char logbuf[1024];
	memset(logbuf , 0x00 , sizeof(logbuf));
//	enum enumproxy {NO_PROXY , AUTO_CONFIG , MANUAL_CONFIG};

//	int bSuccess = 0;

	if (!::WinHttpGetIEProxyConfigForCurrentUser(&ieProxyConfig))
	{
		
		Socket::PrintLog(1 , "[FAIL] blastsock::FindProxyFromWinHttp / WinHttpGetIEProxyConfigForCurrentUser\r\n");

		//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
		m_ProxyData = *m_pSelectedProxyData;

		goto NEXT;
	}
	
	wsprintf(logbuf , "ieProxyConfig ==>\r\n\t(AutoDetect : %d)\r\n\t(configUrl : %S)\r\n\t(szProxy : %S)\r\n\t(proxyBypass : %S)\r\n" , 
		ieProxyConfig.fAutoDetect , ieProxyConfig.lpszAutoConfigUrl , ieProxyConfig.lpszProxy , ieProxyConfig.lpszProxyBypass);
    Socket::PrintLog(1 , logbuf);

//	Socket::PrintLog(1 , "blastsock::FindProxyFromWinHttp / 1 \r\n");
	//PAC 방식이면

	if(ieProxyConfig.lpszAutoConfigUrl != NULL) //auto config
	{
		wsprintf(logbuf , "[SUCCESS] Get PAC file (%S) \r\n" , ieProxyConfig.lpszAutoConfigUrl);
		Socket::PrintLog(1 , logbuf);
	
		if(strlen((LPSTR)ieProxyConfig.lpszAutoConfigUrl))
		{
			AutoProxyOptions.lpszAutoConfigUrl = ieProxyConfig.lpszAutoConfigUrl;

			hHttpSession = WinHttpOpen( 0 ,
				WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
				WINHTTP_NO_PROXY_NAME,
				WINHTTP_NO_PROXY_BYPASS,
				WINHTTP_FLAG_ASYNC);
			
			// Exit if WinHttpOpen failed.
			if( !hHttpSession )
			{
				Socket::PrintLog(1 , "[FAIL] WinHttpOpen \r\n" );
				//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
				m_ProxyData = *m_pSelectedProxyData;
				goto NEXT;
			}	
			
				// Use auto-detection because the Proxy 
			// Auto-Config URL is not known.
			AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
			
			// Use DHCP and DNS-based auto-detection.
			AutoProxyOptions.dwAutoDetectFlags = 
				WINHTTP_AUTO_DETECT_TYPE_DHCP |
				WINHTTP_AUTO_DETECT_TYPE_DNS_A;
			
			// If obtaining the PAC script requires NTLM/Negotiate
			// authentication, then automatically supply the client
			// domain credentials.
			AutoProxyOptions.fAutoLogonIfChallenged = TRUE;
			
			AutoProxyOptions.lpszAutoConfigUrl = ieProxyConfig.lpszAutoConfigUrl;
			
			if( WinHttpGetProxyForUrl( hHttpSession,
				L"http://www.anysupport.net",
				&AutoProxyOptions,
				&ProxyInfo))
			{
			
				if(ProxyInfo.lpszProxy == NULL)
				{
					//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
					m_ProxyData = *m_pSelectedProxyData;
					goto NEXT;
				}

				if(strlen((LPSTR)ProxyInfo.lpszProxy) == 0 )
				{
					//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
					m_ProxyData = *m_pSelectedProxyData;
					goto NEXT;
				}

				wsprintf(logbuf , "[SUCCESS] Get PAC Proxy Info (%S) \r\n" , ProxyInfo.lpszProxy);
				Socket::PrintLog(1 , logbuf);

				char buf[1024];
				memset(buf , 0x00 ,sizeof(buf));
				
				//strcpy(buf , (LPSTR)ProxyInfo.lpszProxy);
				wsprintf(buf , "%S" , ProxyInfo.lpszProxy);
				
				char*tok = NULL;
				
				if( (tok = strchr(buf, ';')) != NULL)
				{
					char temp[256];
					memset(temp , 0x00 , sizeof(temp));
					
					char temp1[256];
					memset(temp1 , 0x00 , sizeof(temp1));
					
					strncpy(temp , buf , strlen(buf)-strlen(tok));
					
					if((tok = strchr(temp , ':')) != NULL)
					{
						strncpy(temp1 , temp , strlen(temp)-strlen(tok));
						m_pSelectedProxyData->SetProxyHost(temp1);
						strcpy(temp , tok+1 );
						m_pSelectedProxyData->SetProxyPort((SHORT)atoi(temp));

						m_pSelectedProxyData->SetType(PROXYTYPE_HTTP11);
						m_ProxyData = *m_pSelectedProxyData;
						Socket::PrintLog(1 , "[SUCCESS] Get PAC Proxy IP:Port (%s:%d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());
						goto END;
					}
					else
					{
						//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
						m_ProxyData = *m_pSelectedProxyData;
						Socket::PrintLog(1 , "[FAIL] Get PAC Proxy IP:Port -1 \r\n");
						goto NEXT;
					}
				}
				else
				{
					if( (tok = strchr(buf, ':')) != NULL)
					{
						char temp[256];
						memset(temp , 0x00 , sizeof(temp));
						
						strncpy(temp , buf , strlen(buf)-strlen(tok));
						m_pSelectedProxyData->SetProxyHost(temp);
						
						memset(temp , 0x00 , sizeof(temp));
						strcpy(temp , tok+1 );
						m_pSelectedProxyData->SetProxyPort((SHORT)atoi(temp));
						
						m_pSelectedProxyData->SetType(PROXYTYPE_HTTP11);
						m_ProxyData = *m_pSelectedProxyData;
						Socket::PrintLog(1 , "[SUCCESS] Get PAC Proxy IP:Port (%s:%d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());
						goto END;
					}
					else
					{
						//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
						m_ProxyData = *m_pSelectedProxyData;
						Socket::PrintLog(1 , "[FAIL] Get PAC Proxy IP:Port -2 \r\n");
						goto NEXT;
					}
				}

			}
			else
			{
				//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
				m_ProxyData = *m_pSelectedProxyData;
				Socket::PrintLog(1 , "[fail] Get PAC Proxy Info \r\n");
				goto NEXT;
			}
				
		}
	}

NEXT:

	if(ieProxyConfig.lpszProxy != NULL) //manual config
	{
		if(strlen((LPSTR)ieProxyConfig.lpszProxy)) //수동 방식이면
		{
			Socket::PrintLog(1 , "[SUCCESS] Get Manual Proxy Info from IE(%S) \r\n" , ieProxyConfig.lpszProxy);
			char buf[256];
			memset(buf , 0x00 ,sizeof(buf));
			wsprintf(buf , "%S" , ieProxyConfig.lpszProxy);
			char*tok = NULL;
			
			if( (tok = strchr(buf, ':')) != NULL)
			{
				char temp[256];
				memset(temp , 0x00 , sizeof(temp));
				
				strncpy(temp , buf , strlen(buf)-strlen(tok));
				m_pSelectedProxyData->SetProxyHost(temp);
				
				memset(temp , 0x00 , sizeof(temp));
				strcpy(temp , tok+1 );
				m_pSelectedProxyData->SetProxyPort((SHORT)atoi(temp));
				
				m_pSelectedProxyData->SetType(PROXYTYPE_HTTP11);
				m_ProxyData = *m_pSelectedProxyData;

				Socket::PrintLog(1 , "[SUCCESS] Get Manual IE Proxy IP:Port (%s:%d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());
				goto END;
			}
			else
			{
				//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
				m_ProxyData = *m_pSelectedProxyData;
				Socket::PrintLog(1 , "[fail] Get Manual IE Proxy IP:Port -1  \r\n");
				goto END;
			}
		}
		else //proxy 환경이 아님..
		{
			Socket::PrintLog(1 , "blastsock::FindProxyFromWinHttp / No Proxy Env \r\n");
			
			//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
			m_ProxyData = *m_pSelectedProxyData;

			Socket::PrintLog(1 , "[fail] Get Manual IE Proxy IP:Port -2 \r\n");
			goto END;
		}
	}
	else
	{
		Socket::PrintLog(1 , "blastsock::FindProxyFromWinHttp / No Proxy Env \r\n");
		
		//m_pSelectedProxyData->SetType(PROXYTYPE_NOPROXY);
		m_ProxyData = *m_pSelectedProxyData;
	}

END :
	//
	// Clean up the WINHTTP_PROXY_INFO structure.
	//
	if( ieProxyConfig.lpszAutoConfigUrl != NULL )
		GlobalFree(ieProxyConfig.lpszAutoConfigUrl);

	if( ieProxyConfig.lpszProxyBypass != NULL )
		GlobalFree(ieProxyConfig.lpszProxyBypass);

	if( ieProxyConfig.lpszProxy != NULL )
		GlobalFree(ieProxyConfig.lpszProxy);


    if( ProxyInfo.lpszProxy != NULL )
		GlobalFree(ProxyInfo.lpszProxy);
	
    if( ProxyInfo.lpszProxyBypass != NULL )
		GlobalFree( ProxyInfo.lpszProxyBypass );
	
	//
	// Close the WinHTTP handles.
	//
    if( hRequest != NULL )
		WinHttpCloseHandle( hRequest );
	
    if( hConnect != NULL )
		WinHttpCloseHandle( hConnect );
	
    if( hHttpSession != NULL )
		WinHttpCloseHandle( hHttpSession );

	return true;
}

BOOL blastsock::IsWinXPorLater()
{
	DWORD	g_platform_id;
	BOOL	g_impersonating_user = 0;
	DWORD	g_version_major;
	DWORD	g_version_minor;
	
	OSVERSIONINFO osversioninfo;
    osversioninfo.dwOSVersionInfoSize = sizeof(osversioninfo);
	
	// Get the current OS version
    if (!GetVersionEx(&osversioninfo))
		g_platform_id = 0;
    g_platform_id = osversioninfo.dwPlatformId;
	g_version_major = osversioninfo.dwMajorVersion;
	g_version_minor = osversioninfo.dwMinorVersion;
	
	if(g_platform_id == VER_PLATFORM_WIN32_NT)
	{
		if( (g_version_major==5 && g_version_minor>=1) || 
			g_version_major>=6) return TRUE;
	}
	return FALSE;
}

HANDLE blastsock::GetToken()
{
	HANDLE hProcess,hPToken;
	DWORD dwSessionId, dwExplorerLogonPid = -1, dwExplorerLogonPid2 = -1;
	
	// 세션 ID 얻기
	typedef DWORD (WINAPI* pWTSGetActiveConsoleSessionId)(VOID);
	typedef BOOL (WINAPI* pProcessIdToSessionId)(DWORD, DWORD*);
	
	pWTSGetActiveConsoleSessionId WTSGetActiveConsoleSessionIdF=NULL;
	pProcessIdToSessionId pProcessIdToSessionIdF = NULL;
	
	HMODULE hlibkernel = LoadLibrary("kernel32.dll");
	WTSGetActiveConsoleSessionIdF=(pWTSGetActiveConsoleSessionId)GetProcAddress(hlibkernel, "WTSGetActiveConsoleSessionId"); 
	pProcessIdToSessionIdF=(pProcessIdToSessionId)GetProcAddress(hlibkernel, "ProcessIdToSessionId"); 
	FreeLibrary(hlibkernel);
	
	if(WTSGetActiveConsoleSessionIdF == NULL || pProcessIdToSessionIdF == NULL) return NULL;
	
	dwSessionId = WTSGetActiveConsoleSessionIdF();
	
	// 프로세스 ID 얻기
	PROCESSENTRY32 procEntry;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
	procEntry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnap, &procEntry))
    {
        return FALSE;
    }
	
	do
    {
		// Explorer.exe의 프로세스 ID를 얻어온다
        if (_stricmp(procEntry.szExeFile, "explorer.exe") == 0)
        {
			DWORD dwExplorerSessId = 0;
			if(pProcessIdToSessionIdF(procEntry.th32ProcessID, &dwExplorerSessId))
			{
				if (dwExplorerSessId == dwSessionId)
				{
					dwExplorerLogonPid = procEntry.th32ProcessID;
					break;
				}
				else
				{
					dwExplorerLogonPid2 = procEntry.th32ProcessID;
				}
			}
			else
			{

			}
        }
		
    } while (Process32Next(hSnap, &procEntry));

	if(dwExplorerLogonPid == -1)
	{
		dwExplorerLogonPid = dwExplorerLogonPid2;
	}
	if(dwExplorerLogonPid == -1)
	{
		dwExplorerLogonPid = 0;
	}
	
	hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,dwExplorerLogonPid);
	
	if(!::OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
		|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
		|TOKEN_READ|TOKEN_WRITE,&hPToken))
	{
		int abcd = GetLastError();
		printf("Process token open Error: %u\n",GetLastError()); 
	}
	
	return hPToken;
}

