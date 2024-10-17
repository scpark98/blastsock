// SocketsInitializer.cpp: implementation of the SocketsInitializer class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "SocketsInitializer.h"
#include "Socket.h"



//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

SocketsInitializer::SocketsInitializer()
{
	Socket::StartSockets();
}

SocketsInitializer::~SocketsInitializer()
{
	Socket::ShutdownSockets();
}

