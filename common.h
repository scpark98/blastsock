#pragma once


#include "stdafx.h"
#include <fcntl.h>

#include <mmsystem.h>
const char DEBUGFILENAME[ 30 ] = "debug.txt";

#define DEFAULT_HOST_PORT 8888
#define DEFAULT_CONTENT_LENGTH (100 * 1024) /* bytes */
#define DEFAULT_KEEP_ALIVE 5 /* seconds */
#define DEFAULT_MAX_CONNECTION_AGE 300 /* seconds */
#define BUG_REPORT_EMAIL "bug-httptunnel@gnu.org"
///*typedef */struct Arg
//{
//  char me[32];
//  char device[128];
//  char host[16];
//  int port;
//  char forward_host[16];
//  int forward_port;
//  size_t content_length;
//  char pid_filename[255];
//  int use_std;
//  int use_daemon;
//  int strict_content_length;
//  int keep_alive;
//  int max_connection_age;
//} /*Arguments*/;

struct Arg{
	char me[ 32 ];
	char device[128];
	char host_name[16];
	int	 host_port;
	char proxy_name[64];
	int proxy_port;
	size_t proxy_buffer_size;
	int proxy_buffer_timeout;
	size_t content_length;
	int forward_port;
	int use_std;
	int use_daemon;
	int strict_content_length;
	int keep_alive;
	int max_connection_age;
	char proxy_authorization[128];
	char user_agent[128];
	char proxy_user[ 32 ];
	char proxy_psw[32];
	char proxy_domain[32];
};


static  bool  HasFile(const char *name)
{
	HANDLE	file;
	WIN32_FIND_DATA	filedata;

	file=FindFirstFile(name,&filedata);

	if(file == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		FindClose(file);
		return true;
	}

	return false;
}

static void _addfilename(char *filename,int size)
{
	int i=size-1,j=0;

	while(filename[i] != '.')
		i--;

	i--;

	while(true)
	{
		if(filename[i-j] == '9')
			filename[i-j]='0';
		else
		{
			filename[i-j]++;

			break;
		}

		j++;
	}
}

static  void  _format_str(char *buf,char *text,...)
{
	va_list ap;

	va_start(ap,text);
	vsprintf(buf,text,ap);
	va_end(ap);
}

static  void  OutputLog(char *text,...)
{
	
	static DWORD num=0;
	static char filename[] = "debug000.log";
	char buf[102400];
	FILE *fp=NULL;

	va_list ap;

	va_start(ap,text);
	vsprintf(buf,text,ap);
	va_end(ap);	

	if(num == 0)
	{
#ifdef _ZEPHYR_MUL_DEBUG
		while(HasFile(filename))
			_addfilename(filename,sizeof(filename));

		fp=fopen(filename,"w");
#else
		fp=fopen(DEBUGFILENAME,"w");
#endif
	}
	else
	{
#ifdef _ZEPHYR_MUL_DEBUG
		fp=fopen(filename,"a");
#else
		fp=fopen(DEBUGFILENAME,"a");
#endif
	}

	if(fp == NULL)
		return ;

	num++;


	SYSTEMTIME time;

	GetLocalTime(&time);

	
	fprintf(fp, "%d: %s - %d/%d/%d %d:%d:%d \n", num, buf, time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);


	fclose(fp);
}
static  void  debug(char *text,...)
{
	

	char buf[102400];

	va_list ap;

	va_start(ap,text);
	vsprintf(buf,text,ap);
	va_end(ap);	

	OutputLog(buf);
}

static int
set_address (struct sockaddr_in *address, const char *host, int port)
{
  memset (address, '\0', sizeof *address);
#if defined(__FreeBSD__) || defined(__OpenBSD__)
  address->sin_len = sizeof *address;
#endif
  address->sin_family = PF_INET;
  address->sin_port = htons ((u_short)port);
  address->sin_addr.s_addr = inet_addr (host);

  if (address->sin_addr.s_addr == INADDR_NONE)
    {
      struct hostent *ent;
      unsigned int ip;

      debug ("set_address: gethostbyname (\"%s\")", host);
      ent = gethostbyname (host);
      debug ("set_address: ent = %p", ent);
      if (ent == 0)
	return -1;

      memcpy(&address->sin_addr.s_addr, ent->h_addr, (unsigned)ent->h_length);
      ip = ntohl (address->sin_addr.s_addr);
      debug ("set_address: host = %d.%d.%d.%d",
		     ntohl (ip) >> 24,
		    (ntohl (ip) >> 16) & 0xff,
		    (ntohl (ip) >>  8) & 0xff,
		     ntohl (ip)        & 0xff);
    }

  return 0;
}

static int
open_device (char *device)
{
 // struct termios t;
  int fd=-1;

 // fd = open (device, O_RDWR /*| O_NONBLOCK*/);
 // if (fd == -1)
 //   return -1;
 // 
 // if (tcgetattr (fd, &t) == -1)
 //   {
 //     if (errno == ENOTTY || errno == EINVAL)
	//return fd;
 //     else
	//return -1;
 //   }
 // t.c_iflag = 0;
 // t.c_oflag = 0;
 // t.c_lflag = 0;
 // if (tcsetattr (fd, TCSANOW, &t) == -1)
 //   return -1;

  return fd;
}

