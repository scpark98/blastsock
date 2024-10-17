// Typical use:
//
//       Log neturoLog;
//       neturoLog.SetFile( _T("myapp.log") );
//       ...
//       neturoLog.Print(2, _T("x = %d\n"), x);
//

#ifndef BLASTLOG_H__
#define BLASTLOG_H__

#pragma once

#include <stdarg.h>
#include <string>
#include "log_base64.h"
#include <tchar.h>
#include <time.h>
#define TAB	"\t"


class BlastLog
{
public:
	BlastLog(int level = 0 , bool append = false)
	{
		InitializeCriticalSection(&m_criticalLog);
		m_level = level;
		m_append = append;
		
		hlogfile = NULL;
		m_bEncrypt = true;
	};

	bool StartLog(LPTSTR filename = NULL , bool bEncrypt = true)
	{
		if(filename == NULL)
			return false;

		m_bEncrypt = bEncrypt;
		if(hlogfile)
		{
			CloseFile();
		}

		if(!hlogfile)
		{
			hlogfile = CreateFile(
				filename,  GENERIC_WRITE, FILE_SHARE_READ, NULL,
				OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL  );
			
			if (hlogfile == INVALID_HANDLE_VALUE) {
				// We should throw an exception here
/*
				char newfile[MAX_PATH];
				memset(newfile , 0x00 , sizeof(newfile));
				sprintf(newfile , "%s_double.log" , filename);
				hlogfile = CreateFile(
					newfile ,  GENERIC_WRITE, FILE_SHARE_READ, NULL,
				OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL  );
*/
				TCHAR newfile[MAX_PATH];
				memset(newfile , 0x00 , sizeof(newfile));
				_stprintf(newfile , _T("%s_double.log") , filename);
				hlogfile = CreateFile(
					newfile ,  GENERIC_WRITE, FILE_SHARE_READ, NULL,
					OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL  );

				if(hlogfile == INVALID_HANDLE_VALUE)
					return false;
			}

			if (m_append) 
			{
				SetFilePointer( hlogfile, 0, NULL, FILE_END );
			} 
			else 
			{
				SetEndOfFile( hlogfile );
			}

			return true;
		}
		return false;
	};

	//void Print(int depth , LPTSTR format, ...)
	void Print(int depth ,  LPTSTR format, va_list ap)
	{
		if (hlogfile == INVALID_HANDLE_VALUE || hlogfile == NULL) 
			return;

		EnterCriticalSection(&m_criticalLog);
		//va_list ap;
        //va_start(ap, format);
        ReallyPrint(depth , format, ap);
		//va_end(ap);
		LeaveCriticalSection(&m_criticalLog);
	};


	~BlastLog() 
	{
		EnterCriticalSection(&m_criticalLog);
		CloseFile();
		LeaveCriticalSection(&m_criticalLog);
		DeleteCriticalSection(&m_criticalLog);
	};
private:
	void CloseFile() {
		if (hlogfile != NULL) 
		{
			CloseHandle(hlogfile);
			hlogfile = NULL;
		}
	};
	
	void ReallyPrint(int depth  , LPTSTR format, va_list ap)
	{
		time_t current = time(0);
		char time_str[32];
		memset(time_str , 0x00 , 32);

		if(depth > 0 )
		{
			for(int i = 0 ; i < depth ; i++)
				strcat(time_str , TAB);
			strncpy(&time_str[depth] , ctime(&current), 24);
			strcpy(&time_str[depth+24], " : ");
		}
		else
		{
			strncpy(time_str, ctime(&current), 24);
			strcpy(&time_str[24], " : ");
		}

		/*
		TCHAR line[1024];
		_vsntprintf(line, sizeof(line) - 2 * sizeof(TCHAR), format, ap);
		line[1024-2] = (TCHAR)'\0';
		*/
		TCHAR line[4096];
		_vsntprintf(line, sizeof(line) - 2 * sizeof(TCHAR), format, ap);
		line[4096-2] = (TCHAR)'\0';
		int len = _tcslen(line);
 		if (len > 0 && len <= sizeof(line) - 2 * sizeof(TCHAR) && line[len-1] == (TCHAR)'\n') 
 		{
 			// Replace trailing '\n' with MS-DOS style end-of-line.
 			line[len-1] = (TCHAR)'\r';
 			line[len] =   (TCHAR)'\n';
 			line[len+1] = (TCHAR)'\0';
 		}
		
		if (hlogfile != NULL) 
		{
			DWORD byteswritten;
				
			char buf[2048];
			memset(buf , 0x00 ,sizeof(buf));
			sprintf(buf , "%s%s", time_str , line);
			if(m_bEncrypt)
			{
				std::string base64e2 = base64_encode((unsigned char*)buf , strlen(buf));
				WriteFile(hlogfile, (char*)base64e2.c_str(), base64e2.size()*sizeof(TCHAR), &byteswritten, NULL); 
				WriteFile(hlogfile , "\r\n" , 2*sizeof(TCHAR) , &byteswritten , NULL);
			}
			else
			{
				WriteFile(hlogfile, (char*)buf, strlen(buf)*sizeof(TCHAR), &byteswritten, NULL); 
			}

		}
	};

	
	CRITICAL_SECTION m_criticalLog;
    int m_level;
	bool m_append;
    HANDLE hlogfile;
	bool m_bEncrypt;
};


#endif // BLASTLOG_H__

