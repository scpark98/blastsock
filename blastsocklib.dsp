# Microsoft Developer Studio Project File - Name="blastsocklib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=blastsocklib - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "blastsocklib.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "blastsocklib.mak" CFG="blastsocklib - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "blastsocklib - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "blastsocklib - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "blastsocklib - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "./libcryptopp51" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D "_WSPIAPI_COUNTOF" /FD /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE RSC /l 0x412 /d "NDEBUG"
# ADD RSC /l 0x412 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"./Release/blastsocklibR.lib"

!ELSEIF  "$(CFG)" == "blastsocklib - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "./libcryptopp51" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "_WSPIAPI_COUNTOF" /FD /GZ /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE RSC /l 0x412 /d "_DEBUG"
# ADD RSC /l 0x412 /fo"Release/b.res" /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"Debug\blastsocklibD.lib"

!ENDIF 

# Begin Target

# Name "blastsocklib - Win32 Release"
# Name "blastsocklib - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\blastsock.cpp
# End Source File
# Begin Source File

SOURCE=.\d3des.c
# End Source File
# Begin Source File

SOURCE=.\log_base64.cpp
# End Source File
# Begin Source File

SOURCE=.\neturoauth.c
# End Source File
# Begin Source File

SOURCE=.\neturoCrypto.cpp
# End Source File
# Begin Source File

SOURCE=.\NTLM.cpp
# End Source File
# Begin Source File

SOURCE=.\ProxyData.cpp
# End Source File
# Begin Source File

SOURCE=.\ProxyInfo.cpp
# End Source File
# Begin Source File

SOURCE=.\ProxySocket.cpp
# End Source File
# Begin Source File

SOURCE=.\Socket.cpp
# End Source File
# Begin Source File

SOURCE=.\SocketsInitializer.cpp
# End Source File
# Begin Source File

SOURCE=.\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# Begin Source File

SOURCE=.\StringQueue.cpp
# End Source File
# Begin Source File

SOURCE=.\WinINetDownLoader.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\AllNTLM.h
# End Source File
# Begin Source File

SOURCE=.\base64md4.h
# End Source File
# Begin Source File

SOURCE=.\BlastLog.h
# End Source File
# Begin Source File

SOURCE=.\blastsock.h
# End Source File
# Begin Source File

SOURCE=.\blastsocklib.h
# End Source File
# Begin Source File

SOURCE=.\common.h
# End Source File
# Begin Source File

SOURCE=.\d3des.h
# End Source File
# Begin Source File

SOURCE=.\log_base64.h
# End Source File
# Begin Source File

SOURCE=.\md4.h
# End Source File
# Begin Source File

SOURCE=.\neturoauth.h
# End Source File
# Begin Source File

SOURCE=.\neturoCrypto.h
# End Source File
# Begin Source File

SOURCE=.\neturoPassword.h
# End Source File
# Begin Source File

SOURCE=.\NTLM.h
# End Source File
# Begin Source File

SOURCE=.\ProxyData.h
# End Source File
# Begin Source File

SOURCE=.\ProxyInfo.h
# End Source File
# Begin Source File

SOURCE=.\ProxySocket.h
# End Source File
# Begin Source File

SOURCE=.\smades.h
# End Source File
# Begin Source File

SOURCE=.\smbencrypt.h
# End Source File
# Begin Source File

SOURCE=.\Socket.h
# End Source File
# Begin Source File

SOURCE=.\SocketsInitializer.h
# End Source File
# Begin Source File

SOURCE=.\StdAfx.h
# End Source File
# Begin Source File

SOURCE=.\StringQueue.h
# End Source File
# Begin Source File

SOURCE=.\WinINetDownLoader.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\Readme.txt
# End Source File
# End Target
# End Project
