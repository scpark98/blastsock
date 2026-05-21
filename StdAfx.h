#ifndef BLASTSOCK_STDAFX_H
#define BLASTSOCK_STDAFX_H

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

// TODO: reference additional headers your program requires here


// Crypto++에서 c++17을 사용하는 경우 아래 define 필요
// 출처 : https://github.com/weidai11/cryptopp/issues/442

#include "./cryptopp/config.h"
#if (CRYPTOPP_VERSION >= 600) && (__cplusplus >= 201103L)
using byte = CryptoPP::byte;
#else
typedef unsigned char byte;
#endif

//using byte = std::byte;

//#define CRYPTOPP_NO_GLOBAL_BYTE 1 // Crypto++에서 c++17을 사용하는 경우 CRYPTOPP_NO_GLOBAL_BYTE define 필요

#include <winsock2.h>
#include <windows.h>
#include "blastsocklib.h"


//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // #ifndef BLASTSOCK_STDAFX_H