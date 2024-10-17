// StringQueue.cpp: implementation of the StringQueue class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "StringQueue.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

StringQueue::StringQueue(INT nMaxSize)
{
	m_nMaxSize = nMaxSize;
	m_lpQueue = new CHAR[m_nMaxSize];
	m_iFront = m_iRear = 0;
}

StringQueue::~StringQueue()
{
	delete [] m_lpQueue; 
}

//////////////////////////////////////////////////////////////////////
// Operator
//////////////////////////////////////////////////////////////////////

StringQueue& StringQueue::operator= (StringQueue& rhs)
{
	if(this == &rhs) return *this;

	INT rhsQueueSize = rhs.GetSize();
	LPSTR lpBuf = new CHAR[rhsQueueSize];
	rhs.Dequeue(lpBuf, rhsQueueSize);
	rhs.Enqueue(lpBuf, rhsQueueSize);
	this->Enqueue(lpBuf, rhsQueueSize);
	delete [] lpBuf;
	return *this;
}

INT StringQueue::GetSize()
{
	return (m_iRear - m_iFront + m_nMaxSize) % m_nMaxSize;
}

INT StringQueue::GetMaxSize()
{
	return m_nMaxSize;
}

BOOL StringQueue::Enqueue(LPCSTR lpBuffer, INT nEnqueueSize)
{
	if(GetSize() + nEnqueueSize > m_nMaxSize - 1) return FALSE;

	if(m_iRear + nEnqueueSize >= m_nMaxSize)
	{
		memcpy(m_lpQueue + m_iRear + 1, lpBuffer, m_nMaxSize - m_iRear - 1);
		memcpy(m_lpQueue, lpBuffer + m_nMaxSize - m_iRear - 1, nEnqueueSize - m_nMaxSize + m_iRear + 1);
		m_iRear = nEnqueueSize - m_nMaxSize + m_iRear;
	}
	else
	{
		memcpy(m_lpQueue + m_iRear + 1, lpBuffer, nEnqueueSize);
		m_iRear += nEnqueueSize;
	}
	return TRUE;
}

BOOL StringQueue::Dequeue(LPSTR lpBuffer, INT nDequeueSize, int flags)
{
	if(GetSize() < nDequeueSize) return FALSE;

	if(m_iFront + nDequeueSize >= m_nMaxSize)
	{
		memcpy(lpBuffer, m_lpQueue + m_iFront + 1, m_nMaxSize - m_iFront - 1);
		memcpy(lpBuffer + m_nMaxSize - m_iFront - 1, m_lpQueue, nDequeueSize - m_nMaxSize + m_iFront + 1);
		if(flags == 0) m_iFront = nDequeueSize - m_nMaxSize + m_iFront;
	}
	else
	{
		memcpy(lpBuffer, m_lpQueue + m_iFront + 1, nDequeueSize);
		if(flags == 0) m_iFront += nDequeueSize;
	}
	return TRUE;
}