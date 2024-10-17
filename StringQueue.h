// StringQueue.h: interface for the StringQueue class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_STRINGQUEUE_H__CD479487_0F82_415B_82D3_C1792DF20E4C__INCLUDED_)
#define AFX_STRINGQUEUE_H__CD479487_0F82_415B_82D3_C1792DF20E4C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

// queue default size
const int STRINGQUEUE_DEFAULTSIZE = 50000;

class StringQueue  
{
public:
	StringQueue(INT nMaxSize = STRINGQUEUE_DEFAULTSIZE);
	virtual ~StringQueue();

	BOOL Enqueue(LPCSTR lpBuffer, INT nEnqueueSize);
	BOOL Dequeue(LPSTR lpBuffer, INT nDequeueSize, int flags = 0);

	INT GetSize();
	INT GetMaxSize();

	StringQueue& operator= (StringQueue&);
protected:
	LPSTR m_lpQueue;
	INT m_nMaxSize;
	INT m_iFront, m_iRear;
};

#endif // !defined(AFX_STRINGQUEUE_H__CD479487_0F82_415B_82D3_C1792DF20E4C__INCLUDED_)
