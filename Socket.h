#ifndef BLASTSOCK_SOCKET_H
#define BLASTSOCK_SOCKET_H

#include <winsock2.h>

#include "BlastLog.h"
// Socket.h
// general socket wrapper class


// to do : so_linger 처리하기

class Socket  
{
public:
	Socket();
	virtual ~Socket();

	/* logging*/
	bool StartLog(LPTSTR filename = NULL  , bool bEncrypt = true);
	void PrintLog(int depth , LPTSTR format, ...);
	/* */

	bool GetOwnership() const;
	void SetOwnership(bool own);

	operator SOCKET() {return m_s;}
	SOCKET GetSocket() const;
	void AttachSocket(SOCKET s, bool own=false);
	SOCKET DetachSocket();
	bool CloseSocket();

	bool Create(int nType = SOCK_STREAM);
	bool Bind(unsigned int port, const char *addr=NULL);
	bool Bind(const sockaddr* psa, int saLen);
	bool Listen(int backlog=SOMAXCONN);
	//bool Connect(char *addr, unsigned int port);
	//bool Connect(const sockaddr* psa, int saLen);

	bool Connect(char* addr , unsigned int port , bool blocking = false);
	bool Connect(const sockaddr* psa, int saLen , bool blocking = false);

	bool Accept(Socket& s, sockaddr *psa=NULL, int* psaLen=NULL);
	bool GetSockName(sockaddr *psa, int* psaLen);
	int Send(const char* buf, unsigned int bufLen, int flags=0);
	int Recv(char* buf, unsigned int bufLen, int flags=0);
	bool SendExact(const char* buf, unsigned int bufLen);
	bool RecvExact(char* buf, unsigned int bufLen);
	bool RecvUntil(char* buf, unsigned int bufLen, char* delimit);
	bool ShutDown(int how = SD_SEND);

	bool IOCtl(long cmd, unsigned long *argp);
	bool SendReady(const timeval *timeout);
	bool ReceiveReady(const timeval *timeout);

	// start Windows Sockets 2
	static bool StartSockets();
	// calls WSACleanup for Windows Sockets
	static bool ShutdownSockets();
	// returns WSAGetLastError
	static int GetLastError();
	// sets WSASetLastError
	static void SetLastError(int errorCode);
	static unsigned long Inet_Addr(LPCSTR lpAddress);

	void SetTimeout(long millisecs);
	bool SetSockOpt(int level, int optname, const char* optval, int optlen);
	char* Socket::GetPeerName();
	void SetCriticalSection(bool use);

	BlastLog*	kLog;


protected:
	SOCKET m_s;
	bool m_own;
	
	CRITICAL_SECTION m_SendCS;
	CRITICAL_SECTION m_RecvCS;
	bool m_csuse;
};



#endif // #ifndef BLASTSOCK_SOCKET_H

