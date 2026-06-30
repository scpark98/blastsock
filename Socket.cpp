 // Socket.cpp: implementation of the Socket class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Socket.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

Socket::Socket()
{
	m_s = INVALID_SOCKET;
	m_own = false;
	m_csuse = false;

	kLog = NULL;
}

Socket::~Socket()
{
	if(m_own) CloseSocket();
	if(m_csuse)
	{
		DeleteCriticalSection(&m_SendCS);
		DeleteCriticalSection(&m_RecvCS);
	}
}

bool Socket::StartLog(LPTSTR filename   , bool bEncrypt )
{
	if(!kLog)
		kLog = new BlastLog(); 
	else
		return false;
	kLog->StartLog(filename , bEncrypt);
	return true;
}

void Socket::PrintLog(int depth , LPCTSTR format, ...)
{
	if(!kLog)
		return;
	va_list ap;
	va_start(ap, format);
	kLog->Print(depth , format , ap);
	va_end(ap);
}

bool Socket::GetOwnership() const
{
	return m_own;
}

void Socket::SetOwnership(bool own)
{
	m_own = own;
}

SOCKET Socket::GetSocket() const
{
	return m_s;
}

void Socket::AttachSocket(SOCKET s, bool own)
{
	if (m_own)
		CloseSocket();

	m_s = s;
	m_own = own;
}

SOCKET Socket::DetachSocket()
{
	SOCKET s = m_s;
	m_s = INVALID_SOCKET;
	return s;
}

bool Socket::CloseSocket()
{
	if (m_s != INVALID_SOCKET)
	{
		ShutDown(SD_BOTH);
		closesocket(m_s);
		m_s = INVALID_SOCKET;
	}
	return true;
}

bool Socket::Create(int nType)
{
	assert(m_s == INVALID_SOCKET);
	m_s = socket(AF_INET, nType, 0);
	if(m_s == SOCKET_ERROR) 
	{
		m_s = INVALID_SOCKET;
		return false;
	}
	m_own = true;
	return true;
}

bool Socket::Bind(unsigned int port, const char *addr)
{
	sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;

	if (addr == NULL)
		sa.sin_addr.s_addr = htonl(INADDR_ANY);
	else
	{
		unsigned long result = Socket::Inet_Addr(addr);
		if (result == INADDR_NONE)
		{
			SetLastError(WSAEINVAL);
			return false;
		}
		sa.sin_addr.s_addr = result;
	}

	sa.sin_port = htons((u_short)port);

	return Bind((sockaddr *)&sa, sizeof(sa));
}

bool Socket::Bind(const sockaddr *psa, int saLen)
{
	//assert(m_s != INVALID_SOCKET);

	if(bind(m_s, const_cast<sockaddr *>(psa), saLen) == SOCKET_ERROR) return false;
	else return true;
}

bool Socket::Listen(int backlog)
{
	//assert(m_s != INVALID_SOCKET);
	if(listen(m_s, backlog) == SOCKET_ERROR) return false;
	else return true;
}

/*
bool Socket::Connect(char *addr, unsigned int port)
{
	assert(addr != NULL);
	
	sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = Inet_Addr(addr);
	
	if (sa.sin_addr.s_addr == INADDR_NONE)	// Solaris doesn't have INADDR_NONE
	{
		SetLastError(WSAEINVAL);
		return false;
	}
	
	sa.sin_port = htons((u_short)port);
	
	return Connect((const sockaddr *)&sa, sizeof(sa) );
}

bool Socket::Connect(const sockaddr* psa, int saLen)
{
	assert(m_s != INVALID_SOCKET);
	int result = connect(m_s, const_cast<sockaddr*>(psa), saLen);
	if (result == SOCKET_ERROR) return false;
	return true;
}

*/

bool Socket::Connect(const char* addr, unsigned int port, bool blocking)
{
	assert(addr != NULL);

	sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = Inet_Addr(addr);

	if (sa.sin_addr.s_addr == INADDR_NONE)	// Solaris doesn't have INADDR_NONE
	{
		SetLastError(WSAEINVAL);
		return false;
	}

	sa.sin_port = htons((u_short)port);

	return Connect((const sockaddr *)&sa, sizeof(sa) , blocking);
}

bool Socket::Connect(const sockaddr* psa, int saLen , bool blocking)
{
	//assert(m_s != INVALID_SOCKET);
	if(!blocking)
	{
		
		ULONG nonBlk = 1 ;
		struct fd_set fdset;
		struct timeval timevalue;
		
		ioctlsocket(m_s , FIONBIO , &nonBlk);
		connect(m_s, const_cast<sockaddr*>(psa), saLen);
		FD_ZERO(&fdset);
		FD_SET(m_s, &fdset);
		
		// Non-Blocking 모드에서 connect 타임아웃.
		// 5초 → 10초: SYN 재전송 여유 확보
		timevalue.tv_sec = 10;
		timevalue.tv_usec = 0;
		::select(0, NULL, &fdset, NULL, &timevalue);
		if( !FD_ISSET(m_s, &fdset) )
		{
			nonBlk = 0 ;
			ioctlsocket(m_s , FIONBIO , &nonBlk);
			return false;
		}
		else
		{
			PrintLog(0 , "Success Socket::Connect()\r\n");
			nonBlk = 0 ;
			ioctlsocket(m_s , FIONBIO , &nonBlk);
		}
	}
	else
	{
		int result = connect(m_s, const_cast<sockaddr*>(psa), saLen);
		if (result == SOCKET_ERROR) return false;
	}
	//hard close ���� ... ���� ��� ������ �������µ�..�������̶�� �����ų� �ϴ� ������ �ǽɵʿ� ����
	linger l = {1, 0};
	SetSockOpt(SOL_SOCKET, SO_LINGER, (char*)&l, sizeof(l));

	/* IP QOS�� ���� �غ��� ���? �켱������ ���̸� ��Ŷ delay�� ���� ������? 
	QOS qos;
	WSABUF wsbuf;
	wsbuf.buf  = "G.711";
	wsbuf.len = strlen(wsbuf.buf);

	//qos.SendingFlowspec.TokenRate = 65535;
	//qos.SendingFlowspec.TokenBucketSize = 1500;
	//qos.SendingFlowspec.PeakBandwidth

	WSAGetQOSByName(m_s , (LPWSABUF)&wsbuf ,&qos);	

	PrintLog(0 , "QOS : SF(%d / %d / %d / %d / %d / %d / %d / %d )\r\n" , 
		qos.SendingFlowspec.TokenRate ,
		qos.SendingFlowspec.TokenBucketSize , 
		qos.SendingFlowspec.PeakBandwidth,
		qos.SendingFlowspec.Latency,
		qos.SendingFlowspec.DelayVariation,
		qos.SendingFlowspec.ServiceType ,
		qos.SendingFlowspec.MaxSduSize ,
		qos.SendingFlowspec.MinimumPolicedSize );

	PrintLog(0 , "QOS : RF(%d / %d / %d / %d / %d / %d / %d / %d )\r\n" , 
		qos.ReceivingFlowspec.TokenRate ,
		qos.ReceivingFlowspec.TokenBucketSize , 
		qos.ReceivingFlowspec.PeakBandwidth,
		qos.ReceivingFlowspec.Latency,
		qos.ReceivingFlowspec.DelayVariation,
		qos.ReceivingFlowspec.ServiceType ,
		qos.ReceivingFlowspec.MaxSduSize ,
		qos.ReceivingFlowspec.MinimumPolicedSize );

	PrintLog(0 , "QOS : PS(%s\r\n" , 
		qos.ProviderSpecific.buf);
	*/
	//
	return true;
}

bool Socket::Accept(Socket& target, sockaddr *psa, int* psaLen)
{
	//assert(m_s != INVALID_SOCKET);
	SOCKET s = accept(m_s, psa, psaLen);
	if (s == INVALID_SOCKET) return false;
	target.AttachSocket(s, true);
	return true;
}

bool Socket::GetSockName(sockaddr *psa, int* psaLen)
{
	//assert(m_s != INVALID_SOCKET);
	if(getsockname(m_s, psa, psaLen) == SOCKET_ERROR) return false;
	else return true;
}

int Socket::Send(const char* buf, unsigned int bufLen, int flags)
{
	//assert(m_s != INVALID_SOCKET);
	int result = send(m_s, buf, bufLen, flags);
	return result;
}

int Socket::Recv(char* buf, unsigned int bufLen, int flags)
{
	//assert(m_s != INVALID_SOCKET);
	int result = recv(m_s, buf, bufLen, flags);
	return result;
}

bool Socket::SendExact(const char* buf, unsigned int bufLen)
{
	int result;

	if(m_csuse) EnterCriticalSection(&m_SendCS);	
	while(bufLen > 0)
	{
		result = Send(buf, bufLen);
		if(result <= 0)
		{
			m_lastSendError = WSAGetLastError();
			CloseSocket();
			if(m_csuse) LeaveCriticalSection(&m_SendCS);
			return false;
		}
		bufLen -= result;
		buf += result;
	}
	if(m_csuse) LeaveCriticalSection(&m_SendCS);
	return true;
}

bool Socket::RecvExact(char* buf, unsigned int bufLen, int flags)
{
	int result;
	
	if(m_csuse) EnterCriticalSection(&m_RecvCS);	
	while(bufLen > 0)
	{
		result = Recv(buf, bufLen, flags);
		if(result <= 0)
		{
			m_lastRecvError = WSAGetLastError();
			CloseSocket();
			if(m_csuse) LeaveCriticalSection(&m_RecvCS);
			return false;
		}
		bufLen -= result;
		buf += result;
	}
	if(m_csuse) LeaveCriticalSection(&m_RecvCS);
	return true;
}

bool Socket::RecvUntil(char* buf, unsigned int bufLen, const char* delimit)
{
	int delimitLen = strlen(delimit);
	int result;

	ZeroMemory(buf, bufLen);

	while(1)
	{
		if(strlen(buf) == bufLen) return false;
		result = Recv(&buf[strlen(buf)], 1);
		if(result <= 0) return false;
			
		if(strlen(buf) >= delimitLen &&
		   !strncmp(&buf[strlen(buf)-delimitLen] , delimit, delimitLen))
			break;
	}
	return true;
}

bool Socket::ShutDown(int how)
{
	//assert(m_s != INVALID_SOCKET);
	if(shutdown(m_s, how) == SOCKET_ERROR) return false;
	else return true;
}

bool Socket::IOCtl(long cmd, unsigned long *argp)
{
	//assert(m_s != INVALID_SOCKET);
	if(ioctlsocket(m_s, cmd, argp) == SOCKET_ERROR) return false;
	else return true;
}

bool Socket::SendReady(const timeval *timeout)
{
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(m_s, &fds);
	int ready;
	if (timeout == NULL)
		ready = select(m_s+1, NULL, &fds, NULL, NULL);
	else
	{
		timeval timeoutCopy = *timeout;	// select() modified timeout on Linux
		ready = select(m_s+1, NULL, &fds, NULL, &timeoutCopy);
	}

	return ready > 0;
}

bool Socket::ReceiveReady(const timeval *timeout)
{
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(m_s, &fds);
	int ready;
	if (timeout == NULL)
		ready = select(m_s+1, &fds, NULL, NULL, NULL);
	else
	{
		timeval timeoutCopy = *timeout;	// select() modified timeout on Linux
		ready = select(m_s+1, &fds, NULL, NULL, &timeoutCopy);
	}
	return ready > 0;
}

//////////////////////////////////////////////////////
// static method
//////////////////////////////////////////////////////

bool Socket::StartSockets()
{
	WSADATA wsd;
	int result = WSAStartup(0x0002, &wsd);
	if (result != 0) return false;
	else return true;
}

bool Socket::ShutdownSockets()
{
	int result = WSACleanup();
	if (result != 0) return false;
	else return true;
}

int Socket::GetLastError()
{
	return WSAGetLastError();
}

void Socket::SetLastError(int errorCode)
{
	WSASetLastError(errorCode);
}

bool Socket::SetSockOpt(int level, int optname, const char* optval, int optlen)
{
	//assert(m_s != INVALID_SOCKET);
	if(setsockopt(m_s, level, optname, optval, optlen) == SOCKET_ERROR) return false;
	else return true;
}

void Socket::SetTimeout(long millisecs)
{
	int timeout = millisecs;
	SetSockOpt(SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	SetSockOpt(SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
}

char* Socket::GetPeerName()
{
	assert(m_s != INVALID_SOCKET);
	
	struct sockaddr_in	sockinfo;
	struct in_addr		address;
	int 				sockinfosize = sizeof(sockinfo);
	char*				ip;

	// Get the peer address for the client socket
	if(getpeername(m_s, (struct sockaddr *)&sockinfo, &sockinfosize) == SOCKET_ERROR) return NULL;
	memcpy(&address, &sockinfo.sin_addr, sizeof(address));

	ip = inet_ntoa(address);

	return ip;
}

unsigned long Socket::Inet_Addr(LPCSTR lpAddress)
{	// converts a string containing an (Ipv4) Internet Protocol dotted address into a proper address for the IN_ADDR structure
	ULONG ulInetAddr = inet_addr(lpAddress);
	if(ulInetAddr == INADDR_NONE)
	{
		struct hostent *pHost;
		pHost = gethostbyname(lpAddress);
		if(pHost != NULL && pHost->h_addr != NULL)
		{
			sockaddr_in dest;
			memcpy(&(dest.sin_addr), pHost->h_addr, pHost->h_length);
			ulInetAddr = dest.sin_addr.S_un.S_addr;
		}
	}
	return ulInetAddr;
}

void Socket::SetCriticalSection(bool use)
{
	if(m_csuse) 
	{
		DeleteCriticalSection(&m_SendCS);
		DeleteCriticalSection(&m_RecvCS);
	}
	m_csuse = use;
	if(m_csuse)
	{
		InitializeCriticalSection(&m_SendCS);
		InitializeCriticalSection(&m_RecvCS);
	}
}

