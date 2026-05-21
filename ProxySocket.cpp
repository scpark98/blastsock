// ProxySocket.cpp: implementation of the CProxySocket class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "stdio.h"
#include "ProxySocket.h"
#include "base64.h"
#include "WinINetDownLoader.h"




USING_NAMESPACE(CryptoPP)

static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void 
encodeblock( unsigned char in[3], unsigned char out[4], int len )
{
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

void 
base64( char *dst, const char *src, int sz )
{
    unsigned char in[3];
	unsigned char *out = (unsigned char*)dst;
    int i, len;
	
    while (sz > 0)
    {
        len = 0;
        for (i = 0; i < 3; i++, sz--)
        {
            if (sz > 0)
            {
                len++;
                in[i] = src[i];
            } else
                in[i] = 0;
        }
        src += 3;
        if (len)
        {
            encodeblock(in, out, len);
            out += 4;
        }
    }
    *out = '\0';
}

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

ProxySocket::ProxySocket() : Socket()
{
	m_proxyUnAuthorized = false;
}
	
ProxySocket::~ProxySocket()
{
}

void ProxySocket::SetProxyData(CProxyData& ProxyData)
{
	m_ProxyData = ProxyData;
}

bool ProxySocket::Connect(const char* addr, unsigned int port)
{
	bool result = false;

// 	char m_proxyAuthID[64];
// 	char m_proxyAuthPW[64];
// 	
// 	memset(m_proxyAuthID , 0x00 , sizeof(m_proxyAuthID));
// 	memset(m_proxyAuthPW , 0x00 , sizeof(m_proxyAuthPW));
// 	
// 	sprintf(buf, "*** ProxySocket::Connect ***\n");
// 	DbgOutA(buf);
// 	GetProxyIDPW(m_proxyAuthID, m_proxyAuthPW);
// 	
// 	sprintf(buf, "*** ProxySocket id:%s, pw:%s ***\n", m_proxyAuthID, m_proxyAuthPW);
// 	DbgOutA(buf);
// 	if(strlen(m_proxyAuthID) > 0 )
// 	{
// 		m_ProxyData.SetAuth(TRUE);
// 		m_ProxyData.SetUser(m_proxyAuthID);
// 		m_ProxyData.SetPass(m_proxyAuthPW);
// 	}

	// 		m_ProxyData.SetAuth(TRUE);
// 		m_ProxyData.SetUser(m_proxyAuthID);
// 		m_ProxyData.SetPass(m_proxyAuthPW);

	switch(m_ProxyData.GetType())
	{
	case PROXYTYPE_NOPROXY:
		Socket::PrintLog(4 , "ProxySocket::Connect(%s , %d) (PROXYTYPE_NOPROXY) Start\r\n" , addr , port);
		result = ConnectNOPROXY(addr, port);
		break;
	case PROXYTYPE_SOCKS4:
	case PROXYTYPE_SOCKS4A:
		Socket::PrintLog(4 , "ProxySocket::Connect(%s , %d) (PROXYTYPE_SOCKS4) Start\r\n" , addr , port);
		result = ConnectSOCKS4(addr, port);
		break;
	case PROXYTYPE_SOCKS5:
		Socket::PrintLog(4 , "ProxySocket::Connect(%s , %d) (PROXYTYPE_SOCKS5) Start\r\n" , addr , port);
		result = ConnectSOCKS5(addr, port);
		break;
	case PROXYTYPE_HTTP11:
	case PROXYTYPE_HTTP11QUERY:
		Socket::PrintLog(4 , "ProxySocket::Connect(%s , %d) (PROXYTYPE_HTTP11) Start\r\n" , addr , port);
		result = ConnectHTTP11(addr, port);
		break;
	}
	
	if(!result) 
	{
		Socket::PrintLog(5 , "[Error]Failt to Connect ProxySocket::Connect() End\r\n" );
		CloseSocket();
	}
	else
	{
		Socket::PrintLog(5 , "Success to Connect ProxySocket::Connect() End\r\n" );
	}

	return result;
}

bool ProxySocket::ConnectNOPROXY(const char* addr, unsigned int port)
{
	Socket::PrintLog(5 , "ProxySocket::ConnectNOPROXY(%s , %d) Start\r\n" , addr , port);
	if(Socket::Connect(addr, port)) return true;
	WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
	return false;
}

bool ProxySocket::ConnectSOCKS4(const char* addr, unsigned int port)
{
	Socket::PrintLog(5 , "ProxySocket::ConnectSOCKS4(%s , %d) Start\r\n" , addr , port);
	Socket::PrintLog(5 , "Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());

	if(!Socket::Connect(m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort()))
	{
		Socket::PrintLog(5 , "[Error]Fail Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());
		WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
		return false;
	}

	// Make request
	LPSTR lpRequestPacket = new CHAR[9+strlen(addr)+1];
	ZeroMemory(lpRequestPacket, 9+strlen(addr)+1);
	int len = 9;

	// VN is the SOCKS protocol version number and should be 4
	lpRequestPacket[0] = 4; 

	// CD is the SOCKS command code and shoule be 1 for CONNECT request
	lpRequestPacket[1] = 1; 

	// DSTPORT is the destination server's port number
	SHORT lpNBOPort = htons(port);
	memcpy(&lpRequestPacket[2], &lpNBOPort, 2);
		
	// DSTIP 
	// resolve the destination host's damain name
	LONG lInetAddr = Socket::Inet_Addr(addr);

	if(lInetAddr == INADDR_ANY)
	{
		// It allows only SOCKS 4A
		//if(m_ProxyData.GetType() != PROXYTYPE_SOCKS4A) 
		if(m_ProxyData.GetType() != PROXYTYPE_SOCKS4A && m_ProxyData.GetType() != PROXYTYPE_SOCKS4) 
		{
			Socket::PrintLog(5 , "[Error]m_ProxyData.GetType() != PROXYTYPE_SOCKS4A\r\n");
			delete [] lpRequestPacket;
			WSASetLastError(PROXYSOCKET_ERROR_CANTRESOLVEHOST);
			return false;
		}

		// If the client cannot resolve the destination host's domain name to find its IP address,
		// it should set the first three bytes of DSTIP to NULL and the last byte to a non-zero value
		// (This corresponds to IP address 0.0.0.x, with x nonzero.)
		lpRequestPacket[4] = 0;
		lpRequestPacket[5] = 0;
		lpRequestPacket[6] = 0;
		lpRequestPacket[7] = 1;
		
		// Following the NULL byte terminating USERID, 
		// the client must sends the destination domain name and terminates it with another NULL bytes.
		strcpy(&lpRequestPacket[9], addr);
		len += strlen(addr) + 1;
	}
	else
	{
		memcpy(&lpRequestPacket[4], &lInetAddr, 4);
	}
	
	// Send request
	Socket::PrintLog(5 , "Send  PROXYTYPE_SOCKS4 request\r\n");
	if(!SendExact(lpRequestPacket, len))
	{
		Socket::PrintLog(5 , "[error] Could not Send  PROXYTYPE_SOCKS4 request\r\n");
		delete [] lpRequestPacket;
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}
	delete [] lpRequestPacket;

	// Recv response
	char szResponsePacket[8];
	if(!RecvExact(szResponsePacket, 8))
	{
		Socket::PrintLog(5 , "[error] Could not Recv PROXYTYPE_SOCKS4 response\r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	Socket::PrintLog(5 , "Recv PROXYTYPE_SOCKS4 response\r\n");

	if(szResponsePacket[0] != 0)
	{	// VN is the version of the reply code and should be 0
		Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_REQUESTFAILED 1 \r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	if(szResponsePacket[1] != 90)
	{
		Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_REQUESTFAILED 2\r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		if(szResponsePacket[1] == 93) WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
		return false;
	}

	// request granted
	Socket::PrintLog(5 , "ProxySocket::ConnectSOCKS4() end .. request granted\r\n");
	return true;
}

bool ProxySocket::ConnectSOCKS5(const char* addr, unsigned int port)
{
	Socket::PrintLog(5 , "ProxySocket::ConnectSOCKS5(%s , %d) Start\r\n" , addr , port);
	Socket::PrintLog(5 , "Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());


	if(!Socket::Connect(m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort()))
	{
		Socket::PrintLog(5 , "[Error]Fail Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());
		WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
		return false;
	}

	// Send initialization request
	BYTE lpBuffer[10];
	ZeroMemory(lpBuffer, 10);

	// VER is set to 5 for this version of the protocol
	lpBuffer[0] = 5;

	// NMETHOD
	lpBuffer[1] = m_ProxyData.GetAuth() ? 2 : 1;
	
	// METHODS , 2 = user/pass, 0 = no logon
	lpBuffer[2] = m_ProxyData.GetAuth() ? 2 : 0;

	// length of request
	int len = m_ProxyData.GetAuth() ? 4 : 3; 

	Socket::PrintLog(5 , "Send  PROXYTYPE_SOCKS5 request\r\n");
	if(!SendExact((LPCSTR)lpBuffer, len))
	{
		Socket::PrintLog(5 , "[error] Could not Send  PROXYTYPE_SOCKS5 request\r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	// response
	ZeroMemory(lpBuffer, 10);
	if(!RecvExact((LPSTR)lpBuffer, 2))
	{
		Socket::PrintLog(5 , "[error] Could not Recv PROXYTYPE_SOCKS5 response\r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	Socket::PrintLog(5 , "Recv PROXYTYPE_SOCKS5 response\r\n");

	if(lpBuffer[0] != 5)
	{
		Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_REQUESTFAILED 1 \r\n");

		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	if(lpBuffer[1] == 0xFF)
	{
		Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_AUTHFAILED 1 \r\n");

		if(m_ProxyData.GetAuth()) WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
		else WSASetLastError(PROXYSOCKET_ERROR_AUTHREQUIRED);
		return false;
	}

	if(lpBuffer[1])
	{	// Auth needed
		if(lpBuffer[1] != 2)
		{	// Unknown auth type
			Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_AUTHTYPEUNKNOWN 1 \r\n");
			WSASetLastError(PROXYSOCKET_ERROR_AUTHTYPEUNKNOWN);
			return false;
		}

		if(!m_ProxyData.GetAuth())
		{
			Socket::PrintLog(5 , "[error] PROXYSOCKET_ERROR_AUTHNOLOGON 1 \r\n");
			WSASetLastError(PROXYSOCKET_ERROR_AUTHNOLOGON);
			return false;
		}
		
		// Send authentication
		LPBYTE buffer = new BYTE[3+strlen(m_ProxyData.GetUser())+strlen(m_ProxyData.GetPass())+1];
		sprintf((LPSTR)buffer, "  %s %s", m_ProxyData.GetUser(), m_ProxyData.GetPass());
		
		buffer[0] = 5;
		buffer[1] = static_cast<BYTE>(strlen(m_ProxyData.GetUser()));
		buffer[2 + strlen(m_ProxyData.GetUser())] = static_cast<BYTE>(strlen(m_ProxyData.GetPass()));

		int len = 3 + strlen(m_ProxyData.GetUser()) + strlen(m_ProxyData.GetPass());

		Socket::PrintLog(5 , "Send PROXYTYPE_SOCKS5 Authentication (%s , %s) \r\n" , m_ProxyData.GetUser() , m_ProxyData.GetPass());

		if(!SendExact((LPCSTR)buffer, len))
		{
			Socket::PrintLog(5 , "[Error] Could not Send PROXYTYPE_SOCKS5 Authentication (%s , %s) \r\n" , m_ProxyData.GetUser() , m_ProxyData.GetPass());
			delete [] buffer;
			WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
			return false;
		}
		delete [] buffer;

		// Response to the auth request
		if(!RecvExact((LPSTR)lpBuffer, 2))
		{
			Socket::PrintLog(5 , "[Error] Could not Recv PROXYTYPE_SOCKS5 Authentication Response \r\n");
			WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
			return false;
		}

		Socket::PrintLog(5 , "Recv PROXYTYPE_SOCKS5 Authentication Response \r\n" );
		
		if(lpBuffer[1] != 0)
		{
			Socket::PrintLog(5 , "[Error] PROXYSOCKET_ERROR_AUTHFAILED \r\n" );
			WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
			return false;
		}
	}

	// Send Connection Request
	LPSTR command = new CHAR[10 + strlen(addr)+1];
	ZeroMemory(command, 10 + strlen(addr) + 1);
	
	// VER  protocol version is 5
	command[0] = 5;
	
	// CMD  CONNECT = 1 , BIND = 2
	command[1] = 1;
	
	// RSV  RESERVED
	command[2] = 0;

	// ATYP  address type of following address	
	LONG lInetAddr = Socket::Inet_Addr(addr);
	command[3] = lInetAddr?1:3;

	// DST.ADDR desired destination address
	len = 4;
	if(lInetAddr)
	{
		memcpy(&command[len],&lInetAddr,4);
		len += 4;
	}
	else
	{
		command[len] = strlen(addr);
		strcpy(&command[len+1], addr);
		len += strlen(addr) + 1;
	}
	
	// DST.PORT desired destination port in network octet
	SHORT shNBOPort = htons(port);
	memcpy(&command[len], &shNBOPort, 2);
	len+=2;

	Socket::PrintLog(5 , "Send Desired destinatino port(%d) \r\n" , port );

	if(!SendExact(command,len))
	{
		Socket::PrintLog(5 , "[Error] Could not Send Desired destinatino port(%d) \r\n" , port );
		delete [] command;
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	// Response
	if(!RecvExact(command,10))
	{
		Socket::PrintLog(5 , "[Error] Could not recv Desired destinatino port response \r\n");
		delete [] command;
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}
	Socket::PrintLog(5 , "recv Desired destinatino port response \r\n");

	// Check for errors
	if (command[1] != 0 || command[0] != 5)
	{
		Socket::PrintLog(5 , "[Error] PROXYSOCKET_ERROR_REQUESTFAILED 3 \r\n");
		delete [] command;
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}

	Socket::PrintLog(5 , "ProxySocket::ConnectSOCKS5() End ... connection established OK\r\n");
	delete [] command;
	return true;
	// connection established OK
}

bool ProxySocket::ConnectHTTP11(const char* addr, unsigned int port)
{
	Socket::PrintLog(5 , "ProxySocket::ConnectHTTP11(%s , %d) start\r\n" , addr , port);
	Socket::PrintLog(5 , "Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());

	// 테스트 
	char tempAddr[256] = "";
	int tempport = port;
	strcpy(tempAddr, addr);

	if(!Socket::Connect(m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort()))
	{
		Socket::PrintLog(5 , "[Error]Fail Socket::Connect to Proxy(%s , %d) \r\n" , m_ProxyData.GetProxyHost() , m_ProxyData.GetProxyPort());
		
		WSASetLastError(PROXYSOCKET_ERROR_NOCONN);
		return false;
	}

	if(m_ProxyData.GetType() == PROXYTYPE_HTTP11QUERY)
	{
		Socket::PrintLog(5 , "[Error] m_ProxyData.GetType() == PROXYTYPE_HTTP11QUERY \r\n" );
		m_ProxyData.SetDestinationHost(addr);
		m_ProxyData.SetDestinationPort(port);
		return true;
	}

	/*
	CHAR Packet[1024];
	ZeroMemory(Packet, 1024);

	char msgbuf[1024];
	int msgbuflen = sizeof(msgbuf);
	int msglen;
	ZeroMemory(msgbuf, 1024);
	*/

	CHAR Packet[4096];
	ZeroMemory(Packet, 4096);
	
	char msgbuf[4096];
	int msgbuflen = sizeof(msgbuf);
	int msglen;
	ZeroMemory(msgbuf, 4096);
	int idx;

	

	if(!m_ProxyData.GetAuth())
	{	// not authentication
		//sprintf(Packet, "CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\n\r\n", addr, port, addr, port);
		sprintf(Packet, 
			"CONNECT %s:%d HTTP/1.0\r\n"
			"User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;"
			" SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 1.1.4322)\r\n"
			"Host: %s\r\n"
			"Content-Length: 0\r\n"
			"Proxy-Connection: Keep-Alive\r\n"
			"Pragma:no-cache\r\n\r\n",
			tempAddr, port, tempAddr);

		Socket::PrintLog(5 , "No Auth Mode : %s \r\n" , Packet);
	}
	else
	{	// use authentication
		//	sprintf(Packet, "CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\n", addr, port, addr, port);
// 		
// 		LPSTR lpUserPass = new CHAR[strlen(m_ProxyData.GetUser()) + strlen(m_ProxyData.GetPass()) + 2];
// 		ZeroMemory(lpUserPass, strlen(m_ProxyData.GetUser()) + strlen(m_ProxyData.GetPass()) + 2);
// 		sprintf(lpUserPass, "%s:%s", m_ProxyData.GetUser(), m_ProxyData.GetPass());
// 		
// 		byte* encoded = new byte[strlen(lpUserPass)*4+1];
// 		memset(encoded, 0, strlen(lpUserPass)*4+1);
// 		
// 		Base64Encoder base64Encoder;
// 		base64Encoder.Put((unsigned char*)lpUserPass, strlen(lpUserPass));
// 		base64Encoder.MessageEnd();
// 		base64Encoder.Get(encoded, strlen(lpUserPass)*4);

		Socket::PrintLog(5 , "Auth Mode Start \r\n");
/*
		if(!(m_ProxyData.GetUser()!=NULL && strlen(m_ProxyData.GetUser()) >0 && m_ProxyData.GetPass()!=NULL && strlen(m_ProxyData.GetPass())>0)) 
		{
			Socket::PrintLog(5 , "Auto Mode, but id or pw invalid\r\n");
			return false;
		}
*/
		char user_pass[256];
		char encoded[512];

		// 프록시 Basic Key를 만든다.
		int wlen = _snprintf(user_pass, 256, "%s:%s", m_ProxyData.GetUser(), m_ProxyData.GetPass());
		base64(encoded, user_pass, wlen);

		/*
		strcat(Packet, "Authorization: Basic ");
		memcpy(Packet + strlen(Packet), encoded, strlen(lpUserPass)*4);
		strcat(Packet, "\r\n");
		strcat(Packet, "Proxy-Authorization: Basic ");
		memcpy(Packet + strlen(Packet), encoded, strlen(lpUserPass)*4);
		strcat(Packet, "\r\n\r\n");
		*/	
		//sprintf((char*)encoded, "cmFpbm1ha2VyOnJsYWd5Y2pm");

		// NTLM 유저일 경우에는 도메인\유저네임 식으로 아이디가 구성이 되어 있다.
		// 도메인과 유저네임을 파싱한다.
		/*
		char account[256];
		char domain[256];
		char username[256];
		ZeroMemory(account, sizeof(account));
		ZeroMemory(domain, sizeof(domain));
		ZeroMemory(username, sizeof(username));
		
		strcpy(account, m_ProxyData.GetUser());
		if(strstr(account, "\\") != NULL)
		{
			strcpy(domain, strtok(account, "\\"));
			strcpy(username, strtok(NULL, "\\"));	
		}
		else
		{
			strcpy(domain, "DOMAIN");
			strcpy(username, account);	
		}
		
		
		strcpy( m_ntlm.domain, domain);

		char hostname[33];
		memset( hostname,0,sizeof(hostname) );
		::gethostname( hostname, 33 );
		
		for (idx = 0; idx < strlen(hostname); idx++)
		{
			if(hostname[idx] >= 'a' && hostname[idx] <= 'z')
				m_ntlm.myhostname[idx] = hostname[idx] - 'a' + 'A'; // to uppercase letter
		}
		m_ntlm.myhostname[idx] = 0;
		
		//strcpy(m_ntlm.myhostname, "LIGHTCITY");
		//strcpy(m_ntlm.myhostname, "S240E6400");
		
		strcpy( m_ntlm.username, username);
		strcpy( m_ntlm.psw, m_ProxyData.GetPass());
		
		Socket::PrintLog(5 , "NTML domain:%s, hostname:%s, username:%s, userpass:%s\r\n", m_ntlm.domain, m_ntlm.myhostname, m_ntlm.username,  m_ntlm.psw);
		
		msglen = m_ntlm.ntlm_create_msg1( msgbuf,&msgbuflen );

		/*
		sprintf(Packet, 
			"CONNECT %s:%d HTTP/1.0\r\n"
			"User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;"
			" SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 1.1.4322)\r\n"
			"Host: %s:%d\r\n"
			"Content-Length: 0\r\n"
			"Proxy-Connection: Keep-Alive\r\n"
			"Pragma:no-cache\r\n"
			"Proxy-Authorization: Basic %s\r\n"
			"Proxy-Authorization: NTLM %s\r\n\r\n",
		addr, port, addr, port, (char*)encoded, msgbuf);
		*/

		sprintf(Packet, 
			"CONNECT %s:%d HTTP/1.0\r\n"
			"User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;"
			" SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 1.1.4322)\r\n"
			"Host: %s:%d\r\n"
			"Content-Length: 0\r\n"
			"Proxy-Connection: Keep-Alive\r\n"
			"Pragma:no-cache\r\n"
			"Proxy-Authorization: Basic %s\r\n\r\n" ,
			addr, port, addr, port, (char*)encoded);
		//delete [] encoded;
		//delete [] lpUserPass;

		Socket::PrintLog(5 , "Auth Mode : %s \r\n" , Packet);
	}
	

	Socket::PrintLog(5 , "Send  PROXYTYPE_HTTP11 request \r\n");
	if(!SendExact(Packet, strlen(Packet)))
	{
		Socket::PrintLog(5 , "[Error] Could not Send  PROXYTYPE_HTTP11 request \r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}
	
	
	// recv Response
	//if(!RecvUntil(Packet, 1024, "\r\n"))
	if(!RecvUntil(Packet, 4096, "\r\n"))
	{	
		Socket::PrintLog(5 , "[Error] Could not recv  PROXYTYPE_HTTP11 response \r\n");
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
		return false;
	}
	
	Socket::PrintLog(5 , "%s\r\n" , Packet);
	
	strtok(Packet, " ");
	DWORD dwStatusCode = atoi(strtok(NULL, " "));
	
	// 일반적인 프록시 환경이라면 Basic 키가 적용이 되어 여기서 200 OK가 떨어진다.
	if(dwStatusCode == 200)
	{	// established ok
		do 
		{
			//RecvUntil(Packet, 1024, "\r\n");
			RecvUntil(Packet, 4096, "\r\n");
		} 
		while(!(strlen(Packet) == 2 && !strcmp(Packet, "\r\n")));
		
		Socket::PrintLog(5 , "ProxySocket::ConnectHTTP11() end ... 200OK established\r\n");
		return true;
	}
	
	// 만약 NTLM이라면 401 또는 407 에러가 떨어진다.
	if(dwStatusCode == 401 || dwStatusCode == 407)
	{
		Socket::PrintLog(5 , "[Error] Recv %d UnAuthorized\r\n", dwStatusCode);
		
		m_proxyUnAuthorized = true; // 20170809 : 407에러 일때 Proxy 정보 표시

		char strKey[512];
		ZeroMemory(strKey, 512);
		char *pTmp = NULL;
		
		do 
		{
			RecvUntil(Packet, 512, "\r\n");
			pTmp = strstr(Packet, "Proxy-Authenticate: NTLM ");
			if(pTmp != NULL) // NTLM 서버가 응답한 NTLM 키 값을 찾는다. Proxy-Authenticate: NTLM XXXXXX~ 이런식으로 응답이 온다.
			{
				pTmp = pTmp + strlen("Proxy-Authenticate: NTLM ");
				strcpy(strKey, pTmp);
				Socket::PrintLog(5 , "Recved type2 key :%s\r\n", strKey);
			}
			
		} 
		while(!(strlen(Packet) == 2 && !strcmp(Packet, "\r\n")));
		
		if(strlen(strKey) > 0) // NTLM 인증이라면 반드시 키 값이 존재한다. 키를 찾았다면, 안에서 nonce라는 데이터를 추출해 낸다.(type3 메시지 만들때 필요)
		{
			strcpy(msgbuf, strKey);
			//strcpy(msgbuf, "TlRMTVNTUAACAAAAAAAAACgAAAABggAAU3J2Tm9uY2UAAAAAAAAAAA==");
			int valuelen = strlen( msgbuf );
			m_ntlm.ntlm_extract_msg2( msgbuf,&valuelen ); 
			
			Socket::PrintLog(5 , "NTML's nounce is %s\n", m_ntlm.nounce);
			if( strcmp( (const char *)m_ntlm.nounce,"") == 0 )
			{
				Socket::PrintLog(5 , "NTML's nounce is NULL.\r\n");
				return false;
			}
			
			//	strcpy( m_ntlm.username,"u00118" );
			//	strcpy( m_ntlm.psw, "34s1012");
			
			// Type3 메시지를 만들고 최종 전송한다. 문제가 없다면 200 OK가 떨어진다.
			msglen = m_ntlm.ntlm_create_msg3( msgbuf,&msgbuflen ); 
			
			sprintf(Packet, 
				"CONNECT %s:%d HTTP/1.0\r\n"
				"User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;"
				" SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 1.1.4322)\r\n"
				"Host: %s:%d\r\n"
				"Content-Length: 0\r\n"
				"Proxy-Connection: Keep-Alive\r\n"
				"Pragma:no-cache\r\n"
				"Proxy-Authorization: NTLM %s\r\n\r\n",
				addr, port, addr, port, msgbuf);
			
			Socket::PrintLog(5 , "Send  PROXYTYPE_HTTP11 type3 Msg : %s\r\n", Packet);
			
			if(!SendExact(Packet, strlen(Packet)))
			{
				Socket::PrintLog(5 , "[Error] Could not Send  PROXYTYPE_HTTP11 type3 request \r\n");
				WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
				return false;
			}
			Socket::PrintLog(5 , "Send  PROXYTYPE_HTTP11 type3 Msg Success\r\n");
			
			if(!RecvUntil(Packet, 1024, "\r\n"))
			{	
				Socket::PrintLog(5 , "[Error] Could not recv  PROXYTYPE_HTTP11 type3 response \r\n");
				WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
				return false;
			}
			Socket::PrintLog(5 , "Recv  PROXYTYPE_HTTP11 type3 Msg : %s\r\n", Packet);
			strtok(Packet, " ");
			DWORD dwStatusCode = atoi(strtok(NULL, " "));
			
			if(dwStatusCode == 200) // NTLM 인증 완료
			{	// established ok
				do 
				{
					RecvUntil(Packet, 1024, "\r\n");
				} 
				while(!(strlen(Packet) == 2 && !strcmp(Packet, "\r\n")));
				
				Socket::PrintLog(5 , "ProxySocket::ConnectHTTP11() end ... 200OK established\r\n");
				return true;
			}
			
		}
		if(m_ProxyData.GetAuth()) WSASetLastError(PROXYSOCKET_ERROR_AUTHFAILED);
		else WSASetLastError(PROXYSOCKET_ERROR_AUTHREQUIRED);
	} 
	else
	{
		Socket::PrintLog(5 , "[Error] Recv other UnAuthorized err msg(%d)\r\n" , dwStatusCode);
		WSASetLastError(PROXYSOCKET_ERROR_REQUESTFAILED);
	}
	return false;
}

bool ProxySocket::SendHTTPQuery(LPCSTR lpHTTPQuery, INT dwTotalBytesSend)
{
	if(m_ProxyData.GetType() == PROXYTYPE_HTTP11QUERY)
	{
		LPSTR lpProxyHTTPQuery = new CHAR[dwTotalBytesSend + strlen(m_ProxyData.GetProxyHost()) + 20];
		ZeroMemory(lpProxyHTTPQuery, dwTotalBytesSend + strlen(m_ProxyData.GetProxyHost()) + 20);
		
		for(int i=0; i<dwTotalBytesSend; i++)
		{
			if(lpHTTPQuery[i] == ' ')
			{
				// XXX http://host:port/xxxx HTTP/xx 로 만들어준다
				CHAR temp[10]; ZeroMemory(temp, 10);
				strncat(temp, lpHTTPQuery, i);
				sprintf(lpProxyHTTPQuery, "%s http://%s:%d/", temp, m_ProxyData.GetDestinationHost(), m_ProxyData.GetDestinationPort());

				if(lpHTTPQuery[i+1] == '.') i++;
				if(lpHTTPQuery[i+1] == '/') i++;

				strcat(lpProxyHTTPQuery, lpHTTPQuery+i+1);
				
				if(!SendExact(lpProxyHTTPQuery, strlen(lpProxyHTTPQuery)))
				{
					delete [] lpProxyHTTPQuery;
					return false;
				}

				break;
			}
		}

		delete [] lpProxyHTTPQuery;
	}
	else
	{
		if(!SendExact(lpHTTPQuery, dwTotalBytesSend)) return FALSE;
	}

	return true;
}

bool ProxySocket::WinInetConnect(char *strRetVal, int nRetValSize, char *strAgent, char *strServerAddr, int nServerPort, char *strUrl)
{
	Socket::PrintLog(1 , "ProxySocket::WinInetConnect(strAgent:%s strServerAddr:%s nPort:%d strUrl:%s) Start\r\n", strAgent, strServerAddr, nServerPort, strUrl);
	Socket::PrintLog(1 , "Proxy Information(IP:%s, Port:%d, ID:%s, PW:%s\r\n", m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort(), m_ProxyData.GetUser(), m_ProxyData.GetPass());
	WinINetDownLoader winInet;
	DWORD dwStatus;
	DWORD dwStatusSize = sizeof(dwStatus);
	DWORD dwRetValSize = nRetValSize;
	
	//winInet.InternetOpen(strAgent, INTERNET_OPEN_TYPE_PROXY, m_ProxyData.GetProxyHost());
	winInet.InternetOpen(strAgent, INTERNET_OPEN_TYPE_PRECONFIG);
	winInet.InternetConnect(strServerAddr, nServerPort);
	winInet.HttpOpenRequest(strUrl);

	winInet.HttpSendRequest();
	winInet.HttpQueryInfo(HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);

	if(dwStatus == 200)
	{
		winInet.InternetReadFile(strRetVal, dwRetValSize, &dwRetValSize);
		Socket::PrintLog(1 , "ProxySocket::WinInetConnect() 200 OK, retVal:%s\r\n", strRetVal);
		return true;	
	}
	else
	{
		Socket::PrintLog(1 , "ProxySocket::WinInetConnect() failed. Try with proxy basic authentification. error code:%d\r\n", dwStatus);
	}

	if(dwStatus == HTTP_STATUS_PROXY_AUTH_REQ)
	{
		winInet.InternetSetOption(INTERNET_OPTION_PROXY_USERNAME, 
							  m_ProxyData.GetUser(), 
							  strlen(m_ProxyData.GetUser())+1);

		winInet.InternetSetOption(INTERNET_OPTION_PROXY_PASSWORD, 
							  m_ProxyData.GetPass(), 
							  strlen(m_ProxyData.GetPass())+1);
	}
	else if(dwStatus == HTTP_STATUS_DENIED)
	{
		winInet.InternetSetOption(INTERNET_OPTION_USERNAME, 
							  m_ProxyData.GetUser(), 
							  strlen(m_ProxyData.GetUser())+1);

		winInet.InternetSetOption(INTERNET_OPTION_PASSWORD, 
							  m_ProxyData.GetPass(), 
							  strlen(m_ProxyData.GetPass())+1);
	}

	winInet.HttpSendRequest();
	winInet.HttpQueryInfo(HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);

	if(dwStatus == 200)
	{
		winInet.InternetReadFile(strRetVal, dwRetValSize, &dwRetValSize);
		Socket::PrintLog(1 , "ProxySocket::WinInetConnect() 200 OK, retVal:%s\r\n", strRetVal);
		return true;	
	}
	
	Socket::PrintLog(1 , "ProxySocket::WinInetConnect() failed. Try with NTML proxy authentification. error code:%d\r\n", dwStatus);
	winInet.InternetCloseHandle();
	
	char proxyInfo[50]; ZeroMemory(proxyInfo, sizeof(proxyInfo));
	sprintf(proxyInfo, "%s:%d", m_ProxyData.GetProxyHost(), m_ProxyData.GetProxyPort());
	winInet.InternetOpen(strAgent, INTERNET_OPEN_TYPE_PROXY, proxyInfo);
	winInet.InternetConnect(strServerAddr, nServerPort);
	winInet.HttpOpenRequest(strUrl);

	winInet.InternetSetOption(INTERNET_OPTION_PROXY_USERNAME, 
							  m_ProxyData.GetUser(), 
							  strlen(m_ProxyData.GetUser())+1);

	winInet.InternetSetOption(INTERNET_OPTION_PROXY_PASSWORD, 
							  m_ProxyData.GetPass(), 
							  strlen(m_ProxyData.GetPass())+1);

	winInet.HttpSendRequest();
	winInet.HttpQueryInfo(HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);
		
	if(dwStatus == 200)
	{
		winInet.InternetReadFile(strRetVal, dwRetValSize, &dwRetValSize);
		Socket::PrintLog(1 , "ProxySocket::WinInetConnect() 200 OK, retVal:%s\r\n", strRetVal);
		return true;	
	}

	return false;

	
	
/*
	HINTERNET hConnectHandle, hOpenHandle,  hResourceHandle;
	DWORD dwError, dwStatus;
	DWORD dwStatusSize = sizeof(dwStatus);
	char strUsername[64], strPassword[64];
	char buffer[1024], buffer2[1024];
	DWORD sz;
	int i;
	DWORD cchUserLength, cchPasswordLength;
	BOOL fRet;
	DWORD dwIndex;
	strcpy(strUsername, "fc\\u00118");
	strcpy(strPassword, "34s1012");
	cchUserLength = strlen(strUsername);
	cchPasswordLength = strlen(strPassword);

	hOpenHandle = InternetOpen("AnySupport", 
							   INTERNET_OPEN_TYPE_PRECONFIG | INTERNET_OPEN_TYPE_PROXY, 
							   "172.16.1.51", NULL, 0);
	hConnectHandle = InternetConnect(hOpenHandle, 
									 "anysupport.jp", 
									 INTERNET_INVALID_PORT_NUMBER, 
									 NULL,
									 NULL, 
									 INTERNET_SERVICE_HTTP,
									 0,0);
	
	hResourceHandle = HttpOpenRequest(hConnectHandle, "GET",
									  "/ipchk.php",
									  NULL, NULL, NULL, 
									  INTERNET_FLAG_KEEP_CONNECTION, 
									  0);
resend:

	HttpSendRequest(hResourceHandle, NULL, 0, NULL, 0);

	BOOL ret = HttpQueryInfo(hResourceHandle, HTTP_QUERY_FLAG_NUMBER | 
				  HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);
	
	Socket::PrintLog(1, "ret:%d, getlasterror:%d, dwStatus : %d, dwStatusSize:%d\r\n" , ret, GetLastError(), dwStatus, dwStatusSize );
	switch (dwStatus)
	{
		// cchUserLength is the length of strUsername and 
		// cchPasswordLength is the length of strPassword.
	
		dwIndex = 0;
		sz = 1024;
		ZeroMemory(buffer, sizeof(buffer));
		ZeroMemory(buffer2, sizeof(buffer2));
			
		case HTTP_STATUS_PROXY_AUTH_REQ: // Proxy Authentication Required
			// Insert code to set strUsername and strPassword.
			
			// Insert code to safely determine cchUserLength and
			// cchPasswordLength. Insert appropriate error handling code.
			
			//HttpQueryInfo(hResourceHandle, HTTP_QUERY_RAW_HEADERS_CRLF, buffer, &sz, NULL); 

			InternetSetOption(hResourceHandle, 
							  INTERNET_OPTION_PROXY_USERNAME, 
							  strUsername, 
							  cchUserLength+1);

			InternetSetOption(hResourceHandle, 
							  INTERNET_OPTION_PROXY_PASSWORD, 
							  strPassword, 
							  cchPasswordLength+1);
	
			goto resend;
			break;
			
		case HTTP_STATUS_DENIED:     // Server Authentication Required.
			// Insert code to set strUsername and strPassword.
			
			// Insert code to safely determine cchUserLength and 
			// cchPasswordLength. Insert error handling code as 
			// appropriate.
			InternetSetOption(hResourceHandle, INTERNET_OPTION_USERNAME,
							  strUsername, cchUserLength+1);
			InternetSetOption(hResourceHandle, INTERNET_OPTION_PASSWORD,
							  strPassword, cchPasswordLength+1);
			goto resend;
			break;
	}
	return TRUE;
*/
}


// void ProxySocket::GetProxyIDPW(char *proxy_id, char *proxy_pw)
// {
// 	/* 
// 		1. 레지스트리를 뒤져서 이미 저장된 ID/PW가 있으면 그걸 사용한다.
// 		2. 없다면 인증창 다이얼로그를 띄워서 입력받는다.
// 		3. 저장이 체크되어 있으면 레지스트리에 저장하고 리턴한다.
// 		4. 저장이 안되어 있으면 그냥 리턴한다.
// 	*/
// 	HKEY key;
// 	DWORD dwDisp		     = 0;
// 	DWORD temp_size		     = 13;
// 	DWORD temp_size_password = 16;
// 	char temp_id[13];
// 	char temp_password[16];
// 	char temp_reg[255];
// 	
// 	ZeroMemory(temp_id, 13);
// 	ZeroMemory(temp_password, 13);
// 	ZeroMemory(temp_reg, 255);
// 	
// 	//LoadString(g_hRes, IDS_REG_HKEY_LOCAL_MACH, temp_reg, 255);
// 	strcpy(temp_reg, "Software\\Koino\\AnySupport");
// 	RegCreateKeyEx(HKEY_LOCAL_MACHINE, temp_reg, 0, NULL,
// 		REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key,&dwDisp);
// 	
// 	long ret = RegQueryValueEx(key, "Proxy id", 0, NULL,  (unsigned char*)proxy_id, &temp_size);
// 	if(ret == ERROR_SUCCESS)
// 	{
// 		RegQueryValueEx(key, "Proxy id", 0, NULL,  (unsigned char*)proxy_id, &temp_size);
// 		RegCloseKey(key);
// 	}
// 
// 	RegCreateKeyEx(HKEY_LOCAL_MACHINE, temp_reg, 0, NULL,
// 			REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key,&dwDisp);
// 
// 	ret = RegQueryValueEx(key, "Proxy password", 0, NULL,  (unsigned char*)proxy_pw, &temp_size_password);
// 	if(ret == ERROR_SUCCESS)
// 	{
// 		RegQueryValueEx(key, "Proxy password", 0, NULL,  (unsigned char*)proxy_pw, &temp_size_password);
// 		RegCloseKey(key);
// 	}
// }

bool ProxySocket::GetProxyIPPortIfUnAuthorized(char * ip, char * port)
{
	if(m_proxyUnAuthorized) {
		strcpy(ip, m_ProxyData.GetProxyHost());
		sprintf(port, "%d", m_ProxyData.GetProxyPort());
		return true;
	}
	else return false;
}
