#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <process.h>
#include <string.h>
#include <winbase.h>
# include <wincrypt.h>
#define SECURITY_WIN32
# include <Security.h>
# include <Ntsecapi.h>
//# include "smb.h"

//void SmbNegotiate(SMBP * psmbp);
//void SmbSessionSetupAndX1(SMBP * psmbp);
//void SmbSessionSetupAndX2(SMBP * psmbp,wchar_t * username,wchar_t * domainname,wchar_t * password);
void deskey(char * LmPass,unsigned char * desecb);
void passtoowf(wchar_t * password,unsigned char * paswdowf);
void initLMP(char * pass,unsigned char * LM);
void deskey(char * LmPass,unsigned char * desecb);
void des(unsigned char * LM,char * magic,unsigned char * ecb,long no);
void md4init(unsigned char * LM);
void md4(unsigned char * LM);
void md5init(unsigned char * LM);
void md5final(unsigned char * LM);
void initMDP(PLSA_UNICODE_STRING pass,unsigned char * LM);
void hashtocread(unsigned char * enkey,unsigned char * hash,unsigned char * cread);
void challagetorkey(unsigned char * romkey,unsigned char * challage,unsigned char * enkey);
void hmacmd5(unsigned char * rc4key,unsigned char * enkey);
void rc4_key(unsigned char * rc4keylist,unsigned char * rc4key,int keylen);

typedef DWORD (CALLBACK* RTLUPCASEUNICODESTRINGTOOEMSTRING)(PLSA_UNICODE_STRING, PLSA_UNICODE_STRING, DWORD);
RTLUPCASEUNICODESTRINGTOOEMSTRING RtlUpcaseUnicodeStringToOemString;

typedef struct _SMBNBT
{
    unsigned char nbtsmb;
    unsigned char flag;
    short smbpacketlen;
}SMBNBT,* PSMBNBT;

typedef struct _SMBINFO
{
    unsigned char magic[4];
    BYTE smbtoken;
    BYTE errcodeclass;
    BYTE dosaherrcode;
    unsigned char errcode[2];
    BYTE flagsummary;
    short flagsummary2;
    short unuse[6];
    short treeid;
    short callprocessid;
    short userid;
    short multiplexid;
    unsigned char info[2048];
}SMBINFO,* PSMBINFO;

typedef struct _SMBP
{
    SMBNBT smbnbt;
    SMBINFO smbinfo;
}SMBP,* PSMBP;

wchar_t navos[]=L"windows 2000 2195";
wchar_t lanman[]=L"windows 2000 5.0";
unsigned char challage[8]={0x53,0xe6,0x97,0x53,0xfb,0x97,0x7c,0x19};
unsigned char romkey[8]={/*20,-30,3,-114,-104,-100,-31,-33*/-116,21,8,79,165,65,7,-102/*0xc7,0x91,0xdd,0xe8,0x5c,0xcd,0xc8,0xde*/};

unsigned char DESParity[]={0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};
unsigned char DESDShift[]={0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0,
0x64,0xCC,0xF9,0x29,0xDF,0xDE,0x86,0x4A,0x81,0x84,9,0x3C,0,0,0,0,
0xFB,0x99,0xE9,8,0xEC,0x87,0x67,0x2F,0x59,0x0FD,0x22,0xF1};

DWORD DESKEY1[]={
0x00000000,0x00000010,0x20000000,0x20000010,0x00010000,0x00010010,0x20010000,0x20010010,
0x00000800,0x00000810,0x20000800,0x20000810,0x00010800,0x00010810,0x20010800,0x20010810,
0x00000020,0x00000030,0x20000020,0x20000030,0x00010020,0x00010030,0x20010020,0x20010030,
0x00000820,0x00000830,0x20000820,0x20000830,0x00010820,0x00010830,0x20010820,0x20010830,
0x00080000,0x00080010,0x20080000,0x20080010,0x00090000,0x00090010,0x20090000,0x20090010,
0x00080800,0x00080810,0x20080800,0x20080810,0x00090800,0x00090810,0x20090800,0x20090810,
0x00080020,0x00080030,0x20080020,0x20080030,0x00090020,0x00090030,0x20090020,0x20090030,
0x00080820,0x00080830,0x20080820,0x20080830,0x00090820,0x00090830,0x20090820,0x20090830};

DWORD DESKEY2[]={
0x00000000,0x02000000,0x00002000,0x02002000,0x00200000,0x02200000,0x00202000,0x02202000,
0x00000004,0x02000004,0x00002004,0x02002004,0x00200004,0x02200004,0x00202004,0x02202004,
0x00000400,0x02000400,0x00002400,0x02002400,0x00200400,0x02200400,0x00202400,0x02202400,
0x00000404,0x02000404,0x00002404,0x02002404,0x00200404,0x02200404,0x00202404,0x02202404,
0x10000000,0x12000000,0x10002000,0x12002000,0x10200000,0x12200000,0x10202000,0x12202000,
0x10000004,0x12000004,0x10002004,0x12002004,0x10200004,0x12200004,0x10202004,0x12202004,
0x10000400,0x12000400,0x10002400,0x12002400,0x10200400,0x12200400,0x10202400,0x12202400,
0x10000404,0x12000404,0x10002404,0x12002404,0x10200404,0x12200404,0x10202404,0x12202404};

DWORD DESKEY3[]={
0x00000000,0x00000001,0x00040000,0x00040001,0x01000000,0x01000001,0x01040000,0x01040001,
0x00000002,0x00000003,0x00040002,0x00040003,0x01000002,0x01000003,0x01040002,0x01040003,
0x00000200,0x00000201,0x00040200,0x00040201,0x01000200,0x01000201,0x01040200,0x01040201,
0x00000202,0x00000203,0x00040202,0x00040203,0x01000202,0x01000203,0x01040202,0x01040203,
0x08000000,0x08000001,0x08040000,0x08040001,0x09000000,0x09000001,0x09040000,0x09040001,
0x08000002,0x08000003,0x08040002,0x08040003,0x09000002,0x09000003,0x09040002,0x09040003,
0x08000200,0x08000201,0x08040200,0x08040201,0x09000200,0x09000201,0x09040200,0x09040201,
0x08000202,0x08000203,0x08040202,0x08040203,0x09000202,0x09000203,0x09040202,0x09040203};

DWORD DESKEY4[]={
0x00000000,0x00100000,0x00000100,0x00100100,0x00000008,0x00100008,0x00000108,0x00100108,
0x00001000,0x00101000,0x00001100,0x00101100,0x00001008,0x00101008,0x00001108,0x00101108,
0x04000000,0x04100000,0x04000100,0x04100100,0x04000008,0x04100008,0x04000108,0x04100108,
0x04001000,0x04101000,0x04001100,0x04101100,0x04001008,0x04101008,0x04001108,0x04101108,
0x00020000,0x00120000,0x00020100,0x00120100,0x00020008,0x00120008,0x00020108,0x00120108,
0x00021000,0x00121000,0x00021100,0x00121100,0x00021008,0x00121008,0x00021108,0x00121108,
0x04020000,0x04120000,0x04020100,0x04120100,0x04020008,0x04120008,0x04020108,0x04120108,
0x04021000,0x04121000,0x04021100,0x04121100,0x04021008,0x04121008,0x04021108,0x04121108};

DWORD DESKEY5[]={
0x00000000,0x10000000,0x00010000,0x10010000,0x00000004,0x10000004,0x00010004,0x10010004,
0x20000000,0x30000000,0x20010000,0x30010000,0x20000004,0x30000004,0x20010004,0x30010004,
0x00100000,0x10100000,0x00110000,0x10110000,0x00100004,0x10100004,0x00110004,0x10110004,
0x20100000,0x30100000,0x20110000,0x30110000,0x20100004,0x30100004,0x20110004,0x30110004,
0x00001000,0x10001000,0x00011000,0x10011000,0x00001004,0x10001004,0x00011004,0x10011004,
0x20001000,0x30001000,0x20011000,0x30011000,0x20001004,0x30001004,0x20011004,0x30011004,
0x00101000,0x10101000,0x00111000,0x10111000,0x00101004,0x10101004,0x00111004,0x10111004,
0x20101000,0x30101000,0x20111000,0x30111000,0x20101004,0x30101004,0x20111004,0x30111004};

DWORD DESKEY6[]={
0x00000000,0x08000000,0x00000008,0x08000008,0x00000400,0x08000400,0x00000408,0x08000408,
0x00020000,0x08020000,0x00020008,0x08020008,0x00020400,0x08020400,0x00020408,0x08020408,
0x00000001,0x08000001,0x00000009,0x08000009,0x00000401,0x08000401,0x00000409,0x08000409,
0x00020001,0x08020001,0x00020009,0x08020009,0x00020401,0x08020401,0x00020409,0x08020409,
0x02000000,0x0A000000,0x02000008,0x0A000008,0x02000400,0x0A000400,0x02000408,0x0A000408,
0x02020000,0x0A020000,0x02020008,0x0A020008,0x02020400,0x0A020400,0x02020408,0x0A020408,
0x02000001,0x0A000001,0x02000009,0x0A000009,0x02000401,0x0A000401,0x02000409,0x0A000409,
0x02020001,0x0A020001,0x02020009,0x0A020009,0x02020401,0x0A020401,0x02020409,0x0A020409};

DWORD DESKEY7[]={
0x00000000,0x00000100,0x00080000,0x00080100,0x01000000,0x01000100,0x01080000,0x01080100,
0x00000010,0x00000110,0x00080010,0x00080110,0x01000010,0x01000110,0x01080010,0x01080110,
0x00200000,0x00200100,0x00280000,0x00280100,0x01200000,0x01200100,0x01280000,0x01280100,
0x00200010,0x00200110,0x00280010,0x00280110,0x01200010,0x01200110,0x01280010,0x01280110,
0x00000200,0x00000300,0x00080200,0x00080300,0x01000200,0x01000300,0x01080200,0x01080300,
0x00000210,0x00000310,0x00080210,0x00080310,0x01000210,0x01000310,0x01080210,0x01080310,
0x00200200,0x00200300,0x00280200,0x00280300,0x01200200,0x01200300,0x01280200,0x01280300,
0x00200210,0x00200310,0x00280210,0x00280310,0x01200210,0x01200310,0x01280210,0x01280310};

DWORD DESKEY8[]={
0x00000000,0x04000000,0x00040000,0x04040000,0x00000002,0x04000002,0x00040002,0x04040002,
0x00002000,0x04002000,0x00042000,0x04042000,0x00002002,0x04002002,0x00042002,0x04042002,
0x00000020,0x04000020,0x00040020,0x04040020,0x00000022,0x04000022,0x00040022,0x04040022,
0x00002020,0x04002020,0x00042020,0x04042020,0x00002022,0x04002022,0x00042022,0x04042022,
0x00000800,0x04000800,0x00040800,0x04040800,0x00000802,0x04000802,0x00040802,0x04040802,
0x00002800,0x04002800,0x00042800,0x04042800,0x00002802,0x04002802,0x00042802,0x04042802,
0x00000820,0x04000820,0x00040820,0x04040820,0x00000822,0x04000822,0x00040822,0x04040822,
0x00002820,0x04002820,0x00042820,0x04042820,0x00002822,0x04002822,0x00042822,0x04042822};

DWORD DESSpBox1[]={
0x02080800,0x00080000,0x02000002,0x02080802,0x02000000,0x00080802,0x00080002,0x02000002,
0x00080802,0x02080800,0x02080000,0x00000802,0x02000802,0x02000000,0x00000000,0x00080002,
0x00080000,0x00000002,0x02000800,0x00080800,0x02080802,0x02080000,0x00000802,0x02000800,
0x00000002,0x00000800,0x00080800,0x02080002,0x00000800,0x02000802,0x02080002,0x00000000,
0x00000000,0x02080802,0x02000800,0x00080002,0x02080800,0x00080000,0x00000802,0x02000800,
0x02080002,0x00000800,0x00080800,0x02000002,0x00080802,0x00000002,0x02000002,0x02080000,
0x02080802,0x00080800,0x02080000,0x02000802,0x02000000,0x00000802,0x00080002,0x00000000,
0x00080000,0x02000000,0x02000802,0x02080800,0x00000002,0x02080002,0x00000800,0x00080802};

DWORD DESSpBox2[]={
0x40108010,0x00000000,0x00108000,0x40100000,0x40000010,0x00008010,0x40008000,0x00108000,
0x00008000,0x40100010,0x00000010,0x40008000,0x00100010,0x40108000,0x40100000,0x00000010,
0x00100000,0x40008010,0x40100010,0x00008000,0x00108010,0x40000000,0x00000000,0x00100010,
0x40008010,0x00108010,0x40108000,0x40000010,0x40000000,0x00100000,0x00008010,0x40108010,
0x00100010,0x40108000,0x40008000,0x00108010,0x40108010,0x00100010,0x40000010,0x00000000,
0x40000000,0x00008010,0x00100000,0x40100010,0x00008000,0x40000000,0x00108010,0x40008010,
0x40108000,0x00008000,0x00000000,0x40000010,0x00000010,0x40108010,0x00108000,0x40100000,
0x40100010,0x00100000,0x00008010,0x40008000,0x40008010,0x00000010,0x40100000,0x00108000};

DWORD DESSpBox3[]={
0x04000001,0x04040100,0x00000100,0x04000101,0x00040001,0x04000000,0x04000101,0x00040100,
0x04000100,0x00040000,0x04040000,0x00000001,0x04040101,0x00000101,0x00000001,0x04040001,
0x00000000,0x00040001,0x04040100,0x00000100,0x00000101,0x04040101,0x00040000,0x04000001,
0x04040001,0x04000100,0x00040101,0x04040000,0x00040100,0x00000000,0x04000000,0x00040101,
0x04040100,0x00000100,0x00000001,0x00040000,0x00000101,0x00040001,0x04040000,0x04000101,
0x00000000,0x04040100,0x00040100,0x04040001,0x00040001,0x04000000,0x04040101,0x00000001,
0x00040101,0x04000001,0x04000000,0x04040101,0x00040000,0x04000100,0x04000101,0x00040100,
0x04000100,0x00000000,0x04040001,0x00000101,0x04000001,0x00040101,0x00000100,0x04040000};

DWORD DESSpBox4[]={
0x00401008,0x10001000,0x00000008,0x10401008,0x00000000,0x10400000,0x10001008,0x00400008,
0x10401000,0x10000008,0x10000000,0x00001008,0x10000008,0x00401008,0x00400000,0x10000000,
0x10400008,0x00401000,0x00001000,0x00000008,0x00401000,0x10001008,0x10400000,0x00001000,
0x00001008,0x00000000,0x00400008,0x10401000,0x10001000,0x10400008,0x10401008,0x00400000,
0x10400008,0x00001008,0x00400000,0x10000008,0x00401000,0x10001000,0x00000008,0x10400000,
0x10001008,0x00000000,0x00001000,0x00400008,0x00000000,0x10400008,0x10401000,0x00001000,
0x10000000,0x10401008,0x00401008,0x00400000,0x10401008,0x00000008,0x10001000,0x00401008,
0x00400008,0x00401000,0x10400000,0x10001008,0x00001008,0x10000000,0x10000008,0x10401000};

DWORD DESSpBox5[]={
0x08000000,0x00010000,0x00000400,0x08010420,0x08010020,0x08000400,0x00010420,0x08010000,
0x00010000,0x00000020,0x08000020,0x00010400,0x08000420,0x08010020,0x08010400,0x00000000,
0x00010400,0x08000000,0x00010020,0x00000420,0x08000400,0x00010420,0x00000000,0x08000020,
0x00000020,0x08000420,0x08010420,0x00010020,0x08010000,0x00000400,0x00000420,0x08010400,
0x08010400,0x08000420,0x00010020,0x08010000,0x00010000,0x00000020,0x08000020,0x08000400,
0x08000000,0x00010400,0x08010420,0x00000000,0x00010420,0x08000000,0x00000400,0x00010020,
0x08000420,0x00000400,0x00000000,0x08010420,0x08010020,0x08010400,0x00000420,0x00010000,
0x00010400,0x08010020,0x08000400,0x00000420,0x00000020,0x00010420,0x08010000,0x08000020};

DWORD DESSpBox6[]={
0x80000040,0x00200040,0x00000000,0x80202000,0x00200040,0x00002000,0x80002040,0x00200000,
0x00002040,0x80202040,0x00202000,0x80000000,0x80002000,0x80000040,0x80200000,0x00202040,
0x00200000,0x80002040,0x80200040,0x00000000,0x00002000,0x00000040,0x80202000,0x80200040,
0x80202040,0x80200000,0x80000000,0x00002040,0x00000040,0x00202000,0x00202040,0x80002000,
0x00002040,0x80000000,0x80002000,0x00202040,0x80202000,0x00200040,0x00000000,0x80002000,
0x80000000,0x00002000,0x80200040,0x00200000,0x00200040,0x80202040,0x00202000,0x00000040,
0x80202040,0x00202000,0x00200000,0x80002040,0x80000040,0x80200000,0x00202040,0x00000000,
0x00002000,0x80000040,0x80002040,0x80202000,0x80200000,0x00002040,0x00000040,0x80200040};

DWORD DESSpBox7[]={
0x00004000,0x00000200,0x01000200,0x01000004,0x01004204,0x00004004,0x00004200,0x00000000,
0x01000000,0x01000204,0x00000204,0x01004000,0x00000004,0x01004200,0x01004000,0x00000204,
0x01000204,0x00004000,0x00004004,0x01004204,0x00000000,0x01000200,0x01000004,0x00004200,
0x01004004,0x00004204,0x01004200,0x00000004,0x00004204,0x01004004,0x00000200,0x01000000,
0x00004204,0x01004000,0x01004004,0x00000204,0x00004000,0x00000200,0x01000000,0x01004004,
0x01000204,0x00004204,0x00004200,0x00000000,0x00000200,0x01000004,0x00000004,0x01000200,
0x00000000,0x01000204,0x01000200,0x00004200,0x00000204,0x00004000,0x01004204,0x01000000,
0x01004200,0x00000004,0x00004004,0x01004204,0x01000004,0x01004200,0x01004000,0x00004004};

DWORD DESSpBox8[]={
0x20800080,0x20820000,0x00020080,0x00000000,0x20020000,0x00800080,0x20800000,0x20820080,
0x00000080,0x20000000,0x00820000,0x00020080,0x00820080,0x20020080,0x20000080,0x20800000,
0x00020000,0x00820080,0x00800080,0x20020000,0x20820080,0x20000080,0x00000000,0x00820000,
0x20000000,0x00800000,0x20020080,0x20800080,0x00800000,0x00020000,0x20820000,0x00000080,
0x00800000,0x00020000,0x20000080,0x20820080,0x00020080,0x20000000,0x00000000,0x00820000,
0x20800080,0x20020080,0x20020000,0x00800080,0x20820000,0x00000080,0x00800080,0x20020000,
0x20820080,0x00800000,0x20800000,0x20000080,0x00820000,0x00020080,0x20020080,0x20800000,
0x00000080,0x20820000,0x00820080,0x00000000,0x20000000,0x20800080,0x00020000,0x00820080};

/*
void main(int argc,char ** argv)
{
    WSADATA WSAData;
    SOCKET sock;
    SOCKADDR_IN addr_in;
    int len;
    char serverip[]="192.168.13.211";
    short port=445;
    WORD olen,nlen;
    unsigned char buf1[0x1000];
    SMBP smbp;
    HMODULE hNtdll = NULL;

    hNtdll = LoadLibrary( "ntdll.dll" );
    if ( !hNtdll )
    {
        printf( "LoadLibrary( NTDLL.DLL ) Error:%d\n", GetLastError() );
        return ;
    }
    RtlUpcaseUnicodeStringToOemString = (RTLUPCASEUNICODESTRINGTOOEMSTRING)
        GetProcAddress(    hNtdll,    "RtlUpcaseUnicodeStringToOemString");
    if (WSAStartup(MAKEWORD(2,0),&WSAData)!=0)
    {
        printf("WSAStartup error.Error:%d\n",WSAGetLastError());
        return;
    }

    addr_in.sin_family=AF_INET;
    addr_in.sin_port=htons(port);
    addr_in.sin_addr.S_un.S_addr=inet_addr(serverip);
    
    if ((sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))==INVALID_SOCKET)
    {
        printf("Socket failed.Error:%d\n",WSAGetLastError());
        return;
    }
    if(WSAConnect(sock,(struct sockaddr *)&addr_in,sizeof(addr_in),NULL,NULL,NULL,NULL)==SOCKET_ERROR)
    {
        printf("Connect failed.Error:%d",WSAGetLastError());
        return;
    }
    SmbNegotiate(&smbp);
    if (send(sock,(unsigned char *)&smbp,ntohs(smbp.smbnbt.smbpacketlen)+4,0)==SOCKET_ERROR)
    {
            printf("Send failed.Error:%d\n",WSAGetLastError());
            return;
    }
    len=recv(sock,buf1,1024,NULL);
    SmbSessionSetupAndX1(&smbp);
    if (send(sock,(unsigned char *)&smbp,ntohs(smbp.smbnbt.smbpacketlen)+4,0)==SOCKET_ERROR)
    {
            printf("Send failed.Error:%d\n",WSAGetLastError());
            return;
    }
    len=recv(sock,buf1,1024,NULL);
    if((buf1[0]==0xff)&&(buf1[1]=='S')&&(buf1[2]=='M')&&(buf1[3]=='B'))
        olen=0x20;
    else if((buf1[4]==0xff)&&(buf1[5]=='S')&&(buf1[6]=='M')&&(buf1[7]=='B'))
        olen=0x24;
    else
        return;
    smbp.smbinfo.userid =  *(WORD *)(buf1+olen-0x4);
    nlen=*(WORD *)(buf1+olen+1+2*3);//BLOB的长度
    olen=olen+1+2*buf1[olen]+2;
    memcpy(challage,buf1+olen+0x18,8);
    SmbSessionSetupAndX2(&smbp,L"administrator",L"FXNB",L"asdasd");
    if (send(sock,(unsigned char *)&smbp,ntohs(smbp.smbnbt.smbpacketlen)+4,0)==SOCKET_ERROR)
    {
            printf("Send failed.Error:%d\n",WSAGetLastError());
            return;
    }
    len=recv(sock,buf1,1024,NULL);
    if((buf1[0]==0xff)&&(buf1[1]=='S')&&(buf1[2]=='M')&&(buf1[3]=='B'))
        olen=0x20;
    else if((buf1[4]==0xff)&&(buf1[5]=='S')&&(buf1[6]=='M')&&(buf1[7]=='B'))
        olen=0x24;
    else
        return;
    if(buf1[olen]==0)
        printf("error username and password\n");
    else
        printf("login ok\n");
    WSACleanup();
    return;
}
*/

void SmbSessionSetupAndX1(SMBP * psmbp)
{
    unsigned char sb[0x20]={
0x4E,0x54,0x4C,0x4D,0x53,0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x97,0x82,0x08,0xE0,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    psmbp->smbinfo.smbtoken =0x73; 
    memset(psmbp->smbinfo.info,0,0x200); 
    psmbp->smbinfo.flagsummary2 = 0xc807;
    *(DWORD *)(psmbp->smbinfo.info+21) = 0x800000D4;
    //指定使用加密的FLAG
    psmbp->smbinfo.info[0]=0xc;//WORD 参数个数
    *(WORD *)(psmbp->smbinfo.info+1)=0Xff;//无下一个命令
    *(WORD *)(psmbp->smbinfo.info+3)=0Xb0;//下一命令偏移
    *(WORD *)(psmbp->smbinfo.info+5)=0X4104;//最大缓冲
    *(WORD *)(psmbp->smbinfo.info+7)=0X32;//最大的MPX
    *(WORD *)(psmbp->smbinfo.info+9)=0X0;//虚拟通道
    *(DWORD *)(psmbp->smbinfo.info+11)=0X0;//虚拟通道
    *(DWORD *)(psmbp->smbinfo.info+17)=0X0;//保留

    *(WORD *)(psmbp->smbinfo.info+15)=0x20;  //BLOB的长度
    memcpy(psmbp->smbinfo.info+27,sb,0x20);//放入BLOB
    memcpy(psmbp->smbinfo.info+28+0x20,navos,36);//
    memcpy(psmbp->smbinfo.info+66+0x20,lanman,32);//
    *(WORD *)(psmbp->smbinfo.info+25)=73+0x20;
    psmbp->smbnbt.smbpacketlen = htons(132+0x20);
}

void SmbSessionSetupAndX2(SMBP * psmbp,wchar_t * username,wchar_t * domainname,wchar_t * password)
{
    unsigned char enkey[8];
    unsigned char cread[0x40];
    unsigned char passwordhash[0x20];
    unsigned char creaded[0x100];
    int ulen;
    int dlen;
    int i;
    for(i=0;i<0x20;i++)
    {
        if(username[i]==0)
            break;
    }
    ulen=2*i;
    for(i=0;i<0x20;i++)
    {
        if(domainname[i]==0)
            break;
    }
    dlen=2*i;

    memset(creaded,0,0x100);
    memcpy(creaded,"NTLMSSP",8);
    *(DWORD *)(creaded+8)=3;
    *(WORD *)(creaded+0xc)=0x18;
    *(WORD *)(creaded+0xe)=0x18;
    *(DWORD *)(creaded+0x10)=0x40+ulen+dlen+dlen;
    *(WORD *)(creaded+0x14)=0x18;
    *(WORD *)(creaded+0x16)=0x18;
    *(DWORD *)(creaded+0x18)=0x40+ulen+dlen+dlen+0x18;
    *(WORD *)(creaded+0x1c)=dlen;
    *(WORD *)(creaded+0x1e)=dlen;
    *(DWORD *)(creaded+0x20)=0x40;
    *(WORD *)(creaded+0x24)=ulen;
    *(WORD *)(creaded+0x26)=ulen;
    *(DWORD *)(creaded+0x28)=0x40+dlen;
    *(WORD *)(creaded+0x2c)=dlen;
    *(WORD *)(creaded+0x2e)=dlen;
    *(DWORD *)(creaded+0x30)=0x40+dlen+ulen;
    *(WORD *)(creaded+0x34)=0x10;
    *(WORD *)(creaded+0x36)=0x10;
    *(DWORD *)(creaded+0x38)=0x40+ulen+dlen+dlen+0x30;
    *(DWORD *)(creaded+0x3C)=0XE0888215;
    //放如用户名等信息
    memcpy(creaded+0x40,domainname,dlen);
    memcpy(creaded+0x40+dlen,username,ulen);
    memcpy(creaded+0x40+dlen+ulen,domainname,dlen);
    psmbp->smbinfo.smbtoken =0x73; 
    memset(psmbp->smbinfo.info,0,0x200); 
    psmbp->smbinfo.flagsummary2 = 0xc807;
    *(DWORD *)(psmbp->smbinfo.info+21) = 0x800000D4;
    //指定使用加密的FLAG
    psmbp->smbinfo.info[0]=0xc;//WORD 参数个数
    *(WORD *)(psmbp->smbinfo.info+1)=0Xff;//无下一个命令
    *(WORD *)(psmbp->smbinfo.info+3)=0X12e;//下一命令偏移
    *(WORD *)(psmbp->smbinfo.info+5)=0X4104;//最大缓冲
    *(WORD *)(psmbp->smbinfo.info+7)=0X32;//最大的MPX
    *(WORD *)(psmbp->smbinfo.info+9)=0X0;//虚拟通道
    *(DWORD *)(psmbp->smbinfo.info+11)=0X0;//虚拟通道
    *(DWORD *)(psmbp->smbinfo.info+17)=0X0;//保留

    passtoowf(password,passwordhash);    //口令到散列
    challagetorkey(romkey,challage,enkey);    //把挑战和任意一个本地随机KEY通过MD5计算出加密KEY
    memset(cread,0,0x40);
    memcpy(cread,romkey,0x8);    //BLOB中放入本地随机KEY，好让服务器知道能计算出加密KEY
    hashtocread(enkey,passwordhash,cread);    //通过加密KEY计算NTLM的加密形式
    memcpy(creaded+0x40+ulen+dlen+dlen,cread,0x40);    
    *(WORD *)(psmbp->smbinfo.info+15)=0x80+ulen+dlen+dlen;  //BLOB的长度
    memcpy(psmbp->smbinfo.info+27,creaded,0x80+ulen+dlen+dlen);//放入BLOB
    memcpy(psmbp->smbinfo.info+28+0x80+ulen+dlen+dlen,navos,36);//
    memcpy(psmbp->smbinfo.info+66+0x80+ulen+dlen+dlen,lanman,32);//
    *(WORD *)(psmbp->smbinfo.info+25)=73+0x80+ulen+dlen+dlen;
    psmbp->smbnbt.smbpacketlen = htons(132+ 0x80+ulen+dlen+dlen);
}

//void CreateMsg3(/*SMBP * psmbp,*/wchar_t * username,wchar_t * domainname,wchar_t * password)
//{
//    unsigned char enkey[8];
//    unsigned char cread[0x40];
//    unsigned char passwordhash[0x20];
//    unsigned char creaded[0x100];
//    int ulen;
//    int dlen;
//    int i;
//    for(i=0;i<0x20;i++)
//    {
//        if(username[i]==0)
//            break;
//    }
//    ulen=2*i;
//    for(i=0;i<0x20;i++)
//    {
//        if(domainname[i]==0)
//            break;
//    }
//    dlen=2*i;
//
//    memset(creaded,0,0x100);
//    memcpy(creaded,"NTLMSSP",8);
//    *(DWORD *)(creaded+8)=3;
//    *(WORD *)(creaded+0xc)=0x18;
//    *(WORD *)(creaded+0xe)=0x18;
//    *(DWORD *)(creaded+0x10)=0x40+ulen+dlen+dlen;
//    *(WORD *)(creaded+0x14)=0x18;
//    *(WORD *)(creaded+0x16)=0x18;
//    *(DWORD *)(creaded+0x18)=0x40+ulen+dlen+dlen+0x18;
//    *(WORD *)(creaded+0x1c)=dlen;
//    *(WORD *)(creaded+0x1e)=dlen;
//    *(DWORD *)(creaded+0x20)=0x40;
//    *(WORD *)(creaded+0x24)=ulen;
//    *(WORD *)(creaded+0x26)=ulen;
//    *(DWORD *)(creaded+0x28)=0x40+dlen;
//    *(WORD *)(creaded+0x2c)=dlen;
//    *(WORD *)(creaded+0x2e)=dlen;
//    *(DWORD *)(creaded+0x30)=0x40+dlen+ulen;
//    *(WORD *)(creaded+0x34)=0x10;
//    *(WORD *)(creaded+0x36)=0x10;
//    *(DWORD *)(creaded+0x38)=0x40+ulen+dlen+dlen+0x30;
//    *(DWORD *)(creaded+0x3C)=0XE0888215;
//    //放如用户名等信息
//    memcpy(creaded+0x40,domainname,dlen);
//    memcpy(creaded+0x40+dlen,username,ulen);
//    memcpy(creaded+0x40+dlen+ulen,domainname,dlen);
//    psmbp->smbinfo.smbtoken =0x73; 
//    memset(psmbp->smbinfo.info,0,0x200); 
//    psmbp->smbinfo.flagsummary2 = 0xc807;
//    *(DWORD *)(psmbp->smbinfo.info+21) = 0x800000D4;
//    //指定使用加密的FLAG
//    psmbp->smbinfo.info[0]=0xc;//WORD 参数个数
//    *(WORD *)(psmbp->smbinfo.info+1)=0Xff;//无下一个命令
//    *(WORD *)(psmbp->smbinfo.info+3)=0X12e;//下一命令偏移
//    *(WORD *)(psmbp->smbinfo.info+5)=0X4104;//最大缓冲
//    *(WORD *)(psmbp->smbinfo.info+7)=0X32;//最大的MPX
//    *(WORD *)(psmbp->smbinfo.info+9)=0X0;//虚拟通道
//    *(DWORD *)(psmbp->smbinfo.info+11)=0X0;//虚拟通道
//    *(DWORD *)(psmbp->smbinfo.info+17)=0X0;//保留
//
//    passtoowf(password,passwordhash);    //口令到散列
//    challagetorkey(romkey,challage,enkey);    //把挑战和任意一个本地随机KEY通过MD5计算出加密KEY
//    memset(cread,0,0x40);
//    memcpy(cread,romkey,0x8);    //BLOB中放入本地随机KEY，好让服务器知道能计算出加密KEY
//    hashtocread(enkey,passwordhash,cread);    //通过加密KEY计算NTLM的加密形式
//    memcpy(creaded+0x40+ulen+dlen+dlen,cread,0x40);    
//    *(WORD *)(psmbp->smbinfo.info+15)=0x80+ulen+dlen+dlen;  //BLOB的长度
//    memcpy(psmbp->smbinfo.info+27,creaded,0x80+ulen+dlen+dlen);//放入BLOB
//    memcpy(psmbp->smbinfo.info+28+0x80+ulen+dlen+dlen,navos,36);//
//    memcpy(psmbp->smbinfo.info+66+0x80+ulen+dlen+dlen,lanman,32);//
//    *(WORD *)(psmbp->smbinfo.info+25)=73+0x80+ulen+dlen+dlen;
//    psmbp->smbnbt.smbpacketlen = htons(132+ 0x80+ulen+dlen+dlen);
//}

void SmbNegotiate(SMBP * psmbp)
{
    unsigned char magic[4]={0xff,'S','M','B'};
    short len;
    char langitem1[]="PC NETWORK PROGRAM 1.0";
    char langitem2[]="LANMAN1.0";
    char langitem3[]="Windows for Workgroups 3.1a";
    char langitem4[]="LM1.2X002";
    char langitem5[]="LANMAN2.1";
    char langitem6[]="NT LM 0.12";
    char langitem7[]="PCLAN1.0";
    char langitem8[]="MICROSOFT NETWORKS 1.03";
    char langitem9[]="MICROSOFT NETWORKS 3.0";
    char langitem10[]="DOS LM1.2X002";
    char langitem11[]="DOS LANMAN2.1";
    char langitem12[]="Cairo 0.xa";

    memset(psmbp,0,sizeof(SMBP));
    psmbp->smbnbt.nbtsmb = 0;
    psmbp->smbnbt.flag = 0;
    memcpy(psmbp->smbinfo.magic, magic,4);
    psmbp->smbinfo.smbtoken = 0x72; 
    psmbp->smbinfo.errcodeclass = 0x0;
    psmbp->smbinfo.dosaherrcode = 0x0;
    psmbp->smbinfo.errcode[0] = 0x0;
    psmbp->smbinfo.errcode[1] = 0x0;
    psmbp->smbinfo.flagsummary = 0x18;
    psmbp->smbinfo.flagsummary2 = 0xc853;
    //指定了带挑战方式支持的FLAG
    psmbp->smbinfo.callprocessid = 0xfeff;
    psmbp->smbinfo.multiplexid = 0;
    psmbp->smbinfo.info[0]=0x0;
    len=3+2*(psmbp->smbinfo.info[0]);
    psmbp->smbinfo.info[len]=0x2;
    memcpy(psmbp->smbinfo.info+len+1,langitem6,sizeof(langitem6));
    len = len+1+sizeof(langitem6);

    *(WORD *)(psmbp->smbinfo.info+1) =len-3-2*(psmbp->smbinfo.info[0]);
    psmbp->smbnbt.smbpacketlen = htons(len+0x20); 
}

static void challagetorkey(unsigned char * romkey,unsigned char * challage,unsigned char * enkey)
{
    unsigned char LM[0x58];
    md5init(LM);
    *(DWORD *)LM=0x200;
    memcpy(LM+0X18,challage,8);
    memcpy(LM+0X20,romkey,8);
    *(DWORD *)(LM+0x28)=0x80;
    *(DWORD *)(LM+0x50)=0x80;
    md5final(LM);
    memcpy(enkey,LM+8,8);
}

static void hashtocread(unsigned char * enkey,unsigned char * hash,unsigned char * cread)
{
    unsigned char LmPass[0x10];
    unsigned char rc4keylist[0x102];
    LSA_UNICODE_STRING lmhash;
    unsigned char desecb[128];
    unsigned char lm[0x28];
    unsigned char key[0x8];
    unsigned char rc4key[0x10];
//加密KEY加密NTLM
    initLMP((char*)hash,LmPass);
    deskey((char*)LmPass,desecb);
    des(lm,(char*)enkey,desecb,1);
    initLMP((char*)hash+7,LmPass);
    deskey((char*)LmPass,desecb);
    des(lm+8,(char*)enkey,desecb,1);
    memset(key,0,8);
    memcpy(key,hash+0xe,2);
    initLMP((char*)key,LmPass);
    deskey((char*)LmPass,desecb);
    des(lm+0x10,(char*)enkey,desecb,1);
    memcpy(cread+0x18,lm,0x18);
//计算NTLM的RC4形式
    lmhash.Length=0x10;
    lmhash.MaximumLength=0x10;
    lmhash.Buffer= (PWSTR)hash;
    initMDP(&lmhash,rc4key);
    hmacmd5(rc4key,enkey);
    memcpy(cread+0x30,rc4key,0x10);
    rc4_key(rc4keylist,rc4key,0x10);    
//由于并未使用此字段认证，下面的函数未实现，就以RC4KEY做其放进去了
//    rc4_424(rc4keylist,rc4rom,0x10);
}

static void rc4_key(unsigned char * rc4keylist,unsigned char * rc4key,int keylen)
{
    int i,j;
    DWORD a1=0x03020100;
    unsigned char c1,c2,c3;
    for(i=0;i<0x40;i++)
    {
        *(DWORD *)(rc4keylist+4*i)=a1;
        a1+=0x04040404;
    }
    rc4keylist[0x100]=0;
    rc4keylist[0x101]=0;
    j=0;
    i=0;
    c3=0;
    for(j=0;j<0x100;j++)
    {
        c1=rc4keylist[j];
        c2=rc4key[i];
        c3=(c3+c2+c1)%256;
        rc4keylist[j]=rc4keylist[c3];
        rc4keylist[c3]=c1;
        i++;
        if(i==keylen)
            i=0;
    }
}

static void hmacmd5(unsigned char * rc4key,unsigned char * enkey)
{
    unsigned char Lm1[0x58];
    unsigned char Lm2[0x58];
    unsigned char k1[0x40];
    unsigned char k2[0x40];
    int i;
    md5init(Lm1);
    md5init(Lm2);
    memset(k1,0,0x40);
    memset(k2,0,0x40);
    memcpy(k1,rc4key,0x10);
    memcpy(k2,rc4key,0x10);
    for(i=0;i<0x10;i++)
    {
        *(DWORD *)(k1+4*i)=(*(DWORD *)(k1+4*i))^0x36363636;
        *(DWORD *)(k2+4*i)=(*(DWORD *)(k2+4*i))^0x5c5c5c5c;
    }
    *(DWORD *)Lm1=0x200;
    memcpy(Lm1+0X18,k1,0x40);
    md5final(Lm1);
    *(DWORD *)Lm2=0x200;
    memcpy(Lm2+0X18,k2,0x40);
    md5final(Lm2);
    *(DWORD *)Lm1=0x400;
    memcpy(Lm1+0X18,challage,0x8);
    memcpy(Lm1+0X20,romkey,0x8);
    memset(Lm1+0X28,0x80,1);
    memset(Lm1+0X29,0,0x2f);
    *(DWORD *)(Lm1+0x50)=0x280;
    md5final(Lm1);
    memcpy(Lm2+0X18,Lm1+8,0x10);
    *(DWORD *)Lm2=0x400;
    memset(Lm2+0X28,0x80,1);
    memset(Lm2+0X29,0,0x2f);
    *(DWORD *)(Lm2+0x50)=0x280;
    md5final(Lm2);
    memcpy(rc4key,Lm2+8,0x10);
}

static void passtoowf(wchar_t * password,unsigned char * paswdowf)
{
    int len;
    int i;
    LSA_UNICODE_STRING pass;
    LSA_UNICODE_STRING opass;
    char magic1[9]="KGS!@#$%";
    unsigned char desecb[128];
    unsigned char upassword[0x20];
    unsigned char LmPass[0x10];

    len=0;
    for(i=0;i<0x20;i++)
    {
        if(password[i]==0 )
            break;
        len=len+2;
    }
    if(len>28)
    {
        printf("password <=14");
        return;
    }
    pass.Length=len;
    pass.MaximumLength=len;
    pass.Buffer=password;
    opass.MaximumLength=0xf;
    opass.Buffer=(PWSTR)upassword;
    memset(upassword,0,0x10);

	HMODULE hNtdll = NULL;
	hNtdll = LoadLibrary( "ntdll.dll" );
    if ( !hNtdll )
    {
        printf( "LoadLibrary( NTDLL.DLL ) Error:%d\n", GetLastError() );
        return ;
    }
    RtlUpcaseUnicodeStringToOemString = (RTLUPCASEUNICODESTRINGTOOEMSTRING)
        GetProcAddress(    hNtdll,    "RtlUpcaseUnicodeStringToOemString");
   

    RtlUpcaseUnicodeStringToOemString(&opass,&pass,0);
    initLMP((char*)upassword,LmPass);
    deskey((char*)LmPass,desecb);
    des(paswdowf+0x10,magic1,desecb,1);
    initLMP((char*)upassword+7,LmPass);
    deskey((char*)LmPass,desecb);
    des(paswdowf+0x18,magic1,desecb,1);
    initMDP(&pass,paswdowf);
}

static void initMDP(PLSA_UNICODE_STRING pass,unsigned char * LM)
{
    unsigned char LM1[0x58];
    unsigned char s[2]="0";
    md4init(LM1);
    memcpy(LM1+0x18,pass->Buffer,pass->Length);
    memset(LM1+0x18+pass->Length,0x80,1);
    memset(LM1+0x18+pass->Length+1,0,0x37-pass->Length);
    *(DWORD *)(LM1+0x50)=8*(pass->Length);
    memset(LM1+0x51,0x0,7);
    *(DWORD *)(LM1+0x10)=0x200;
    md4(LM1);
    memcpy(LM,LM1,16);
}

static void md4init(unsigned char * LM)
{
    *(DWORD *)(LM)=0x67452301;
    *(DWORD *)(LM+4)=0xefcdab89;
    *(DWORD *)(LM+8)=0x98badcfe;
    *(DWORD *)(LM+0xc)=0x10325476;
    *(DWORD *)(LM+0x10)=0;
    *(DWORD *)(LM+0x14)=0;
}

static void md4(unsigned char * LM)
{
    DWORD d1,d2,d3,d4;
    DWORD a1,a2,a3;
    //第1轮
    d1=*(DWORD *)(LM);
    d2=*(DWORD *)(LM+4);
    d3=*(DWORD *)(LM+8);
    d4=*(DWORD *)(LM+0xc);
    a1=*(DWORD *)(LM+0x18);
    a2=(((d4^d3)&d2)^d4)+a1+d1;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x1c);
    a3=(((d3^d2)&a2)^d3)+a1;
    d4=d4+a3;
    d4=(d4<<7)|(d4>>0x19);
    a1=*(DWORD *)(LM+0x20);
    a3=(((d2^a2)&d4)^d2)+a1;
    d3=d3+a3;
    d3=(d3<<0xb)|(d3>>0x15);
    a1=*(DWORD *)(LM+0x24);
    a3=(((d4^a2)&d3)^a2)+a1;
    d2=d2+a3;
    d2=(d2<<0x13)|(d2>>0xd);
    a1=*(DWORD *)(LM+0x28);
    a3=(((d4^d3)&d2)^d4)+a1;
    a2=a2+a3;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x2c);
    a3=(((d3^d2)&a2)^d3)+a1;
    d4=d4+a3;
    d4=(d4<<7)|(d4>>0x19);
    a1=*(DWORD *)(LM+0x30);
    a3=(((d2^a2)&d4)^d2)+a1;
    d3=d3+a3;
    d3=(d3<<0xb)|(d3>>0x15);
    a1=*(DWORD *)(LM+0x34);
    a3=(((d4^a2)&d3)^a2)+a1;
    d2=d2+a3;
    d2=(d2<<0x13)|(d2>>0xd);
    a1=*(DWORD *)(LM+0x38);
    a3=(((d4^d3)&d2)^d4)+a1;
    a2=a2+a3;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x3c);
    a3=(((d3^d2)&a2)^d3)+a1;
    d4=d4+a3;
    d4=(d4<<7)|(d4>>0x19);
    a1=*(DWORD *)(LM+0x40);
    a3=(((d2^a2)&d4)^d2)+a1;
    d3=d3+a3;
    d3=(d3<<0xb)|(d3>>0x15);
    a1=*(DWORD *)(LM+0x44);
    a3=(((d4^a2)&d3)^a2)+a1;
    d2=d2+a3;
    d2=(d2<<0x13)|(d2>>0xd);
    a1=*(DWORD *)(LM+0x48);
    a3=(((d4^d3)&d2)^d4)+a1;
    a2=a2+a3;
    a2=(a2<<0x3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x4c);
    a3=(((d3^d2)&a2)^d3)+a1;
    d4=d4+a3;
    d4=(d4<<7)|(d4>>0x19);
    a1=*(DWORD *)(LM+0x50);
    a3=(((d2^a2)&d4)^d2)+a1;
    d3=d3+a3;
    d3=(d3<<0xb)|(d3>>0x15);
    a1=*(DWORD *)(LM+0x54);
    a3=(((d4^a2)&d3)^a2)+a1;
    d2=d2+a3;
    d2=(d2<<0x13)|(d2>>0xd);
    //第2轮
    a1=*(DWORD *)(LM+0x18);
    a3=(((d3|d2)&d4)|(d3&d2))+a1+0x5a827999;
    a2=a2+a3;    
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x28);
    a3=(((d2|a2)&d3)|(d2&a2))+0x5a827999;
    d4=d4+a1+a3;
    d4=(d4<<5)|(d4>>0x1b);
    a1=*(DWORD *)(LM+0x38);
    a3=(((d4|a2)&d2)|(d4&a2))+a1+0x5a827999;
    d3=d3+a3;
    d3=(d3<<9)|(d3>>0x17);
    a1=*(DWORD *)(LM+0x48);
    a3=(((d4|d3)&a2)|(d4&d3))+a1+0x5a827999;
    d2=d2+a3;
    d2=(d2<<0xd)|(d2>>0x13);
    a1=*(DWORD *)(LM+0x1c);
    a3=(((d3|d2)&d4)|(d3&d2))+a1+0x5a827999;
    a2=a2+a3;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x2c);
    a3=(((d2|a2)&d3)|(d2&a2))+0x5a827999;
    d4=d4+a1+a3;
    d4=(d4<<5)|(d4>>0x1b);
    a1=*(DWORD *)(LM+0x3c);
    a3=(((d4|a2)&d2)|(d4&a2))+a1+0x5a827999;
    d3=d3+a3;
    d3=(d3<<9)|(d3>>0x17);
    a1=*(DWORD *)(LM+0x4c);
    a3=(((d4|d3)&a2)|(d4&d3))+a1+0x5a827999;
    d2=d2+a3;
    d2=(d2<<0xd)|(d2>>0x13);
    a1=*(DWORD *)(LM+0x20);
    a3=(((d3|d2)&d4)|(d3&d2))+a1+0x5a827999;
    a2=a2+a3;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x30);
    a3=(((d2|a2)&d3)|(d2&a2))+0x5a827999;
    d4=d4+a1+a3;
    d4=(d4<<5)|(d4>>0x1b);
    a1=*(DWORD *)(LM+0x40);
    a3=(((d4|a2)&d2)|(d4&a2))+0x5a827999;
    d3=d3+a1+a3;
    d3=(d3<<9)|(d3>>0x17);
    a1=*(DWORD *)(LM+0x50);
    a3=(((d4|d3)&a2)|(d4&d3))+a1+0x5a827999;
    d2=d2+a3;
    d2=(d2<<0xd)|(d2>>0x13);
    a1=*(DWORD *)(LM+0x24);
    a3=(((d3|d2)&d4)|(d3&d2))+a1+0x5a827999;
    a2=a2+a3;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x34);
    a3=(((d2|a2)&d3)|(d2&a2))+0x5a827999;
    d4=d4+a1+a3;
    d4=(d4<<5)|(d4>>0x1b);
    a1=*(DWORD *)(LM+0x44);
    a3=(((d4|a2)&d2)|(d4&a2))+a1+0x5a827999;
    d3=d3+a3;
    d3=(d3<<9)|(d3>>0x17);    
    a1=*(DWORD *)(LM+0x54);
    a3=(((d4|d3)&a2)|(d4&d3))+a1+0x5a827999;
    d2=d2+a3;
    d2=(d2<<0xd)|(d2>>0x13);    
    //第3轮
    a1=*(DWORD *)(LM+0x18);
    a3=((d4^d3)^d2)+a1;
    a2=a2+0x6ed9eba1+a3;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x38);
    a3=((d3^d2)^a2)+a1;
    d4=d4+0x6ed9eba1+a3;
    d4=(d4<<9)|(d4>>0x17);
    a1=*(DWORD *)(LM+0x28);
    a3=((d4^d2)^a2)+a1;
    d3=d3+0x6ed9eba1+a3;
    d3=(d3<<0xb)|(d3>>0x15);
    a1=*(DWORD *)(LM+0x48);
    a3=d4^d3;
    d2=d2+a1+0x6ed9eba1+(a2^a3);
    d2=(d2<<0xf)|(d2>>0x11);
    a1=*(DWORD *)(LM+0x20);
    a2=a2+((d2^a3)+a1+0x6ed9eba1);
    a3=d3^d2;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x40);
    a3=(a3^a2)+a1;
    d4=d4+0x6ed9eba1+a3;
    d4=(d4<<9)|(d4>>0x17);
    a1=*(DWORD *)(LM+0x30);
    a3=((d4^d2)^a2)+a1;
    d3=d3+0x6ed9eba1+a3;
    d3=(d3<<0xb)|(d3>>0x15);
    a1=*(DWORD *)(LM+0x50);
    a3=d4^d3;
    d2=d2+a1+0x6ed9eba1+(a2^a3);
    d2=(d2<<0xf)|(d2>>0x11);
    a1=*(DWORD *)(LM+0x1c);
    a2=a2+0x6ed9eba1+((d2^a3)+a1);
    a3=d3^d2;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x3c);
    a3=(a3^a2)+a1;
    d4=d4+0x6ed9eba1+a3;
    d4=(d4<<9)|(d4>>0x17);
    a1=*(DWORD *)(LM+0x2c);
    a3=((d4^d2)^a2)+a1;
    d3=d3+0x6ed9eba1+a3;
    d3=(d3<<0xb)|(d3>>0x15);
    a1=*(DWORD *)(LM+0x4c);
    a3=d4^d3;
    d2=d2+a1+0x6ed9eba1+(a2^a3);
    d2=(d2<<0xf)|(d2>>0x11);
    a1=*(DWORD *)(LM+0x24);
    a2=a2+0x6ed9eba1+((d2^a3)+a1);
    a3=d3^d2;
    a2=(a2<<3)|(a2>>0x1d);
    a1=*(DWORD *)(LM+0x44);
    a3=(a3^a2)+a1;
    d4=d4+0x6ed9eba1+a3;
    d4=(d4<<9)|(d4>>0x17);
    a1=*(DWORD *)(LM+0x34);
    a3=((d4^d2)^a2)+a1;
    d3=d3+0x6ed9eba1+a3;
    d3=(d3<<0xb)|(d3>>0x15);
    a1=*(DWORD *)(LM+0x54);
    a3=((d4^a2)^d3)+a1;
    d2=d2+0x6ed9eba1+a3;
    d2=(d2<<0xf)|(d2>>0x11);
    *(DWORD *)(LM)=a2+*(DWORD *)(LM);
    *(DWORD *)(LM+4)=d2+*(DWORD *)(LM+4);
    *(DWORD *)(LM+8)=d3+*(DWORD *)(LM+8);
    *(DWORD *)(LM+0xc)=d4+*(DWORD *)(LM+0xc);
}

static void initLMP(char * pass,unsigned char * LM)
{
    char LmPass[0x20];
    DWORD d1,d2;
    unsigned char a1,a2;
    char a3[]={1,3,7,0xf,0x1f,0x3f,0x7f};
    int i;

    for(i=0;i<8;i++)
    {
        if(i==0)
        {
            a1=pass[0];
            LmPass[0]=a1>>1;
        }
        else if(i==7)
        {
            a1=pass[i-1];
            a1=a1&a3[i-1];            
            LmPass[i]=a1;
        }
        else
        {
            a1=pass[i-1];
            a2=pass[i];
            a1=a1&a3[i-1];
            a1=a1<<(7-i);
            a2=a2>>(i+1);
            LmPass[i]=a1|a2;
        }
    }
    d1=*(DWORD *)LmPass;
    d2=*(DWORD *)(LmPass+4);
    d1=(d1&0xff7f7f7f)<<1;
    d2=(d2&0xff7f7f7f)<<1;
    *(DWORD *)LmPass=d1;
    *(DWORD *)(LmPass+4)=d2;
    //
    for(i=0;i<8;i++)
    {
        a1=LmPass[i];
        a2=a1;
        a1=a1&0xf;
        a2=a2>>4;
        a2=DESParity[a2];
        a1=DESParity[a1];
        a2=a1+a2;
        a2=a2^a1;
        a2=a2-a1;
        a2=a2&1;
        a2=a2^a1;
        a2=a2-a1;
        if(a2==0)
            LmPass[i]=LmPass[i]^1;
    }
    memcpy(LM,LmPass,8);
    //deskey(LmPass,desecb);
    //des(LM,magic1,desecb,1);
}

static void deskey(char * LmPass,unsigned char * desecb)
{
    int i;
    unsigned char a1;
    DWORD d1,d2,d3,d4,d5,d6;


    d1=*(DWORD *)LmPass;
    d2=*(DWORD *)(LmPass+4);
    d2=d2>>4;
    d1=d1&0xf0f0f0f;
    d2=d2&0xf0f0f0f;
    d2=d2^d1;
    d1=(*(DWORD *)LmPass)^d2;
    d2=d2<<4;
    d2=(*(DWORD *)(LmPass+4))^d2;
    d3=d1&0xfffff333;
    d3=d3<<0x12;
    d4=d1&0xcccc0000;
    d4=d4^d3;
    d3=d4;
    d3=d3>>0x12;
    d3=d3^d4;
    d1=d1^d3;
    d3=d2&0xfffff333;
    d3=d3<<0x12;
    d4=d2&0xcccc0000;
    d4=d4^d3;
    d3=d4>>0x12;
    d3=d3^d4;
    d2=d2^d3;
    d3=d1;
    d4=d2>>1;
    d3=d3&0x55555555;
    d4=d4&0x55555555;
    d4=d4^d3;
    d1=d1^d4;
    d4=d4+d4;
    d2=d2^d4;
    d4=d1>>8;
    d3=d2&0xff00ff;
    d4=d4&0xff00ff;
    d4=d4^d3;
    d2=d2^d4;
    d4=d4<<8;
    d1=d1^d4;
    d4=d2>>1;
    d3=d1;
    d3=d3&0x55555555;
    d4=d4&0x55555555;
    d4=d4^d3;
    d1=d1^d4;
    d4=d4+d4;
    d2=d2^d4;
    d3=d1&0xf000000f;
    d4=(d2>>0xc)&0xff0;
    d1=d1&0x0fffffff;
    d3=(d3|d4)>>4;
    d4=d2&0xff00;
    d2=(d2&0xff)<<0x10;
    d3=d3|d4;
    d3=d3|d2;
    for(i=0;i<16;i++)
    {
        d2=d1;
        a1=DESDShift[i];
        if(a1==0)
        {
            d2=d2>>1;
            d1=d1<<0x1b;
            d4=d3>>1;
            d3=d3<<0x1b;
            d1=d1|d2;            
        }
        else
        {
            d2=d2>>2;
            d1=d1<<0x1a;
            d4=d3>>2;
            d3=d3<<0x1a;
            d1=d1|d2;
        }
        d1=d1&0x0fffffff;
        d3=d3|d4;
        d2=d1>>1;
        d4=d1&0xc00000;
        d4=d4|(d2&0x07000000);
        d4=(d4>>1)|(d1&0x00100000);
        //d6=d2&0x00060000;
        d5=(d1&0x0001e000)|(d2&0x00060000);
        d2=d2&0x00000f00;
        d3=d3&0x0fffffff;
        d5=d5>>0xd;
        d4=d4>>0x14;
        d6=DESKEY3[d5];
        d5=d1&0xc0;
        d4=DESKEY4[d4];
        d5=(d5|d2)>>6;
        d4=d4|d6;
        d2=d1&0x3f;
        d6=DESKEY2[d5];
        d5=d3&0x180;
        d4=d4|d6;
        d6=DESKEY1[d2];
        d2=d3>>1;
        d4=d4|d6;
        d6=d2&0x1e00;
        d2=d2&0x6000000;
        d5=(d5^d6)>>7;
        d6=(d3&0x1e00000)|d2;
        d6=d6>>0x15;
        d2=DESKEY6[d5];
        d5=DESKEY8[d6];
        d2=d2^d5;
        d5=d3&0x3f;
        d6=DESKEY5[d5];
        d5=(d3>>0xf)&0x3f;
        d2=d2|d6;
        d6=DESKEY7[d5];
        d5=d4&0xffff;
        d2=d2|d6;
        d6=d2<<0x10;
        d2=d2&0xffff0000;
        d5=d5|d6;
        d5=(d5<<2)|(d5>>0x1e);
        d4=d4>>0x10;
        d2=d2|d4;
        d2=(d2<<6)|(d2>>0x1a);
        *(DWORD *)(desecb+8*i)=d5;
        *(DWORD *)(desecb+8*i+4)=d2;
    }
}

static void des(unsigned char * LM,char * magic,unsigned char * ecb,long no)
{
    DWORD d1,d2,d3,d4;
    DWORD a1,a2,a3;
    int i;
    d1= *(DWORD *)magic;
    d2= *(DWORD *)(magic+4);
    d1 = (d1<<4)|(d1>>0x1c);
    d3 = d1;
    d1 = (d1^d2)&0xf0f0f0f0;
    d3 = d3^d1;
    d2 = d2^d1;
    d2 =(d2<<0x14)|(d2>>0xc);
    d1 = d2;
    d2 = (d2^d3)&0xfff0000f;
    d1 = d1 ^ d2;
    d3 = d3^d2;
    d1 = (d1<<0xe)|(d1>>0x12);
    d2 = d1;
    d1 = (d1 ^ d3) & 0x33333333;
    d2 = d2 ^ d1;
    d3 = d3^d1;
    d3 = (d3<<0x16)|(d3>>0xa);
    d1 = d3;
    d3 = (d3 ^ d2)&0x3fc03fc;
    d1 = d1^d3;
    d2 = d2^d3;
    d1 = (d1<<9)|(d1>>0x17);
    d3 = d1;
    d1 = (d1^d2)&0xaaaaaaaa;
    d3 = d3^d1;
    d2 = d2^d1;
    d2 = (d2<<1)|(d2>>0x1f);
    if(no!=0)
    {
        for(i=0;i<8;i++)
        {
            a1=0;
            d1=*(DWORD *)(ecb+16*i);
            d4=*(DWORD *)(ecb+16*i+4);
            d1=(d1^d3)&0xfcfcfcfc;
            d4=(d4^d3)&0xcfcfcfcf;
            a1=d1&0xff;
            a2=(d1>>8)&0xff;
            d4=(d4>>4)|(d4<<0x1c);
            a3=DESSpBox1[a1/4];
            a1=d4&0xff;
            d2=d2^a3;
            a3=DESSpBox3[a2/4];
            d2=d2^a3;
            a2=(d4>>8)&0xff;
            d1=d1>>0x10;
            a3=DESSpBox2[a1/4];
            d2=d2^a3;
            a1=(d1>>8)&0xff;
            d4=d4>>0x10;
            a3=DESSpBox4[a2/4];
            d2=d2^a3;
            a2=(d4>>8)&0xff;
            d1=d1&0xff;
            d4=d4&0xff;
            a1=DESSpBox7[a1/4];
            d2=d2^a1;
            a1=DESSpBox8[a2/4];
            d2=d2^a1;
            a1=DESSpBox5[d1/4];
            d2=d2^a1;
            a1=DESSpBox6[d4/4];
            d2=d2^a1;

            a1=0;
            d1=*(DWORD *)(ecb+16*i+8);
            d4=*(DWORD *)(ecb+16*i+0xc);
            d1=(d1^d2)&0xfcfcfcfc;
            d4=(d4^d2)&0xcfcfcfcf;
            a1=d1&0xff;
            a2=(d1>>8)&0xff;
            d4=(d4>>4)|(d4<<0x1c);
            a3=DESSpBox1[a1/4];
            a1=d4&0xff;
            d3=d3^a3;
            a3=DESSpBox3[a2/4];
            d3=d3^a3;
            a2=(d4>>8)&0xff;
            d1=d1>>0x10;
            a3=DESSpBox2[a1/4];
            d3=d3^a3;
            a1=(d1>>8)&0xff;
            d4=d4>>0x10;
            a3=DESSpBox4[a2/4];
            d3=d3^a3;
            a2=(d4>>8)&0xff;
            d1=d1&0xff;
            d4=d4&0xff;
            a1=DESSpBox7[a1/4];
            d3=d3^a1;
            a1=DESSpBox8[a2/4];
            d3=d3^a1;
            a1=DESSpBox5[d1/4];
            d3=d3^a1;
            a1=DESSpBox6[d4/4];
            d3=d3^a1;
        }
        d3=(d3>>1)|(d3<<0x1f);
        d1=d2;
        d2=(d2^d3)&0XAAAAAAAA;
        d1=d1^d2;
        d3=d3^d2;
        d1=(d1<<0x17)|(d1>>9);
        d2=d1;
        d1=(d1^d3)&0x3fc03fc;
        d2=(d2^d1);
        d3=d3^d1;
        d2=(d2<<0xa)|(d2>>0x16);
        d1=d2;
        d2=(d2^d3)&0x33333333;
        d1=d1^d2;
        d3=d3^d2;
        d3=(d3<<0x12)|(d3>>0xe);
        d2=d3;
        d3=(d3^d1)&0xfff0000f;
        d2=d2^d3;
        d1=d1^d3;
        d2=(d2<<0xc)|(d2>>0x14);
        d3=d2;
        d2=(d2^d1)&0xf0f0f0f0;
        d3=d3^d2;
        d1=d1^d2;
        d1=(d1>>4)|(d1<<0x1c);
        *(DWORD *)LM=d1;
        *(DWORD *)(LM+4)=d3;
    }
    else
    {
    }
}

static void md5init(unsigned char * LM)
{
    memset(LM,0,0x58);
    *(DWORD *)(LM+8)=0x67452301;
    *(DWORD *)(LM+0xc)=0xefcdab89;
    *(DWORD *)(LM+0x10)=0x98badcfe;
    *(DWORD *)(LM+0x14)=0x10325476;
    *(DWORD *)(LM+0x0)=0;
    *(DWORD *)(LM+0x0)=0;
}

static void md5final(unsigned char * LM)
{
    DWORD a1,d1,d2,s1;
    DWORD b1,b2;
    d1=*(DWORD *)(LM+0XC);
    s1=*(DWORD *)(LM+0X10);
    d2=*(DWORD *)(LM+0X14);
    b2=*(DWORD *)(LM+0X18);
    b1=(((d2^s1)&d1)^d2)+b2;
    b2=*(DWORD *)(LM+0X8);
    b1=b1+b2+0xd76aa478;
    b1=((b1<<0x7)|(b1>>0x19))+d1;
    //第一轮
    b2=*(DWORD *)(LM+0X1c);    
    a1=(((s1^d1)&b1)^s1)+0xe8c7b756;
    d2=d2+b2+a1;
    d2=((d2<<0xc)|(d2>>0x14))+b1;
    b2=*(DWORD *)(LM+0X20);    
    a1=(((d1^b1)&d2)^d1)+0x242070db;
    s1=s1+b2+a1;
    s1=((s1<<0x11)|(s1>>0xf))+d2;
    b2=*(DWORD *)(LM+0X24);    
    a1=(((d2^b1)&s1)^b1)+0xc1bdceee;
    d1=d1+b2+a1;
    d1=((d1<<0x16)|(d1>>0xa))+s1;
    b2=*(DWORD *)(LM+0X28);    
    a1=(((d2^s1)&d1)^d2)+0xf57c0faf;
    b1=b1+b2+a1;
    b1=((b1<<0x7)|(b1>>0x19))+d1;
    b2=*(DWORD *)(LM+0X2c);    
    a1=(((s1^d1)&b1)^s1)+0x4787C62A;
    d2=d2+b2+a1;
    d2=((d2<<0xc)|(d2>>0x14))+b1;    
    b2=*(DWORD *)(LM+0X30);    
    a1=(((d1^b1)&d2)^d1)+0xA8304613;
    s1=s1+b2+a1;
    s1=((s1<<0x11)|(s1>>0xf))+d2;    
    b2=*(DWORD *)(LM+0X34);    
    a1=(((d2^b1)&s1)^b1)+0xFD469501;
    d1=d1+b2+a1;
    d1=((d1<<0x16)|(d1>>0xa))+s1;    
    b2=*(DWORD *)(LM+0X38);    
    a1=(((d2^s1)&d1)^d2)+0x698098D8;
    b1=b1+b2+a1;
    b1=((b1<<0x7)|(b1>>0x19))+d1;
    b2=*(DWORD *)(LM+0X3c);    
    a1=(((s1^d1)&b1)^s1)+0x8B44F7AF;
    d2=d2+b2+a1;
    d2=((d2<<0xc)|(d2>>0x14))+b1;
    b2=*(DWORD *)(LM+0X40);    
    a1=(((d1^b1)&d2)^d1)+0xFFFF5BB1;
    s1=s1+b2+a1;
    s1=((s1<<0x11)|(s1>>0xf))+d2;
    b2=*(DWORD *)(LM+0X44);    
    a1=(((d2^b1)&s1)^b1)+0x895CD7BE;
    d1=d1+b2+a1;
    d1=((d1<<0x16)|(d1>>0xa))+s1;
    b2=*(DWORD *)(LM+0X48);    
    a1=(((d2^s1)&d1)^d2)+0x6B901122;
    b1=b1+b2+a1;
    b1=((b1<<0x7)|(b1>>0x19))+d1;
    b2=*(DWORD *)(LM+0X4c);    
    a1=(((s1^d1)&b1)^s1)+0xFD987193;
    d2=d2+b2+a1;
    d2=((d2<<0xc)|(d2>>0x14))+b1;
    b2=*(DWORD *)(LM+0X50);    
    a1=(((d1^b1)&d2)^d1)+0xA679438E;
    s1=s1+b2+a1;
    s1=((s1<<0x11)|(s1>>0xf))+d2;
    b2=*(DWORD *)(LM+0X54);    
    a1=(((d2^b1)&s1)^b1)+0x49B40821;
    d1=d1+b2+a1;
    d1=((d1<<0x16)|(d1>>0xa))+s1;
    //第二轮
    b2=*(DWORD *)(LM+0X1c);    
    a1=(((s1^d1)&d2)^s1)+0xF61E2562;
    b1=b1+b2+a1;
    b1=((b1<<0x5)|(b1>>0x1b))+d1;
    b2=*(DWORD *)(LM+0X30);    
    a1=(((d1^b1)&s1)^d1)+0xC040B340;
    d2=d2+b2+a1;
    d2=((d2<<0x9)|(d2>>0x17))+b1;
    b2=*(DWORD *)(LM+0X44);    
    a1=(((d2^b1)&d1)^b1)+0x265E5A51;
    s1=s1+b2+a1;
    s1=((s1<<0xe)|(s1>>0x12))+d2;
    b2=*(DWORD *)(LM+0X18);    
    a1=(((d2^s1)&b1)^d2)+0xE9B6C7AA;
    d1=d1+b2+a1;
    d1=((d1<<0x14)|(d1>>0xc))+s1;
    b2=*(DWORD *)(LM+0X2c);    
    a1=(((s1^d1)&d2)^s1)+0xD62F105D;
    b1=b1+b2+a1;
    b1=((b1<<0x5)|(b1>>0x1b))+d1;
    b2=*(DWORD *)(LM+0X40);    
    a1=(((d1^b1)&s1)^d1)+0x2441453;
    d2=d2+b2+a1;
    d2=((d2<<0x9)|(d2>>0x17))+b1;
    b2=*(DWORD *)(LM+0X54);    
    a1=(((d2^b1)&d1)^b1)+0xD8A1E681;
    s1=s1+b2+a1;
    s1=((s1<<0xe)|(s1>>0x12))+d2;
    b2=*(DWORD *)(LM+0X28);    
    a1=(((d2^s1)&b1)^d2)+0xE7D3FBC8;
    d1=d1+b2+a1;
    d1=((d1<<0x14)|(d1>>0xc))+s1;
    b2=*(DWORD *)(LM+0X3c);    
    a1=(((s1^d1)&d2)^s1)+0x21E1CDE6;
    b1=b1+b2+a1;
    b1=((b1<<0x5)|(b1>>0x1b))+d1;
    b2=*(DWORD *)(LM+0X50);    
    a1=(((d1^b1)&s1)^d1)+0xC33707D6;
    d2=d2+b2+a1;
    d2=((d2<<0x9)|(d2>>0x17))+b1;
    b2=*(DWORD *)(LM+0X24);    
    a1=(((d2^b1)&d1)^b1)+0xF4D50D87;
    s1=s1+b2+a1;
    s1=((s1<<0xe)|(s1>>0x12))+d2;
    b2=*(DWORD *)(LM+0X38);    
    a1=(((d2^s1)&b1)^d2)+0x455A14ED;
    d1=d1+b2+a1;
    d1=((d1<<0x14)|(d1>>0xc))+s1;
    b2=*(DWORD *)(LM+0X4c);    
    a1=(((s1^d1)&d2)^s1)+0xA9E3E905;
    b1=b1+b2+a1;
    b1=((b1<<0x5)|(b1>>0x1b))+d1;
    b2=*(DWORD *)(LM+0X20);    
    a1=(((d1^b1)&s1)^d1)+0xFCEFA3F8;
    d2=d2+b2+a1;
    d2=((d2<<0x9)|(d2>>0x17))+b1;
    b2=*(DWORD *)(LM+0X34);    
    a1=(((d2^b1)&d1)^b1)+0x676F02D9;
    s1=s1+b2+a1;
    s1=((s1<<0xe)|(s1>>0x12))+d2;
    b2=*(DWORD *)(LM+0X48);    
    a1=(((d2^s1)&b1)^d2)+0x8D2A4C8A;
    d1=d1+b2+a1;
    d1=((d1<<0x14)|(d1>>0xc))+s1;
    //第三轮
    b2=*(DWORD *)(LM+0X2c);    
    a1=((d2^s1)^d1)+0xFFFA3942;
    b1=b1+b2+a1;
    b1=((b1<<0x4)|(b1>>0x1c))+d1;
    b2=*(DWORD *)(LM+0X38);    
    a1=((s1^d1)^b1)+0x8771F681;
    d2=d2+b2+a1;
    d2=((d2<<0xb)|(d2>>0x15))+b1;
    b2=*(DWORD *)(LM+0X44);    
    a1=(d2^d1)^b1;
    s1=s1+b2+0x6D9D6122+a1;
    s1=((s1<<0x10)|(s1>>0x10))+d2;
    b2=*(DWORD *)(LM+0X50);    
    a1=d2^s1;
    d1=d1+b2+0xFDE5380C+(b1^a1);
    d1=((d1<<0x17)|(d1>>0x9))+s1;
    b2=*(DWORD *)(LM+0X1c);    
    b1=b1+b2+0xA4BEEA44+(d1^a1);
    b1=((b1<<0x4)|(b1>>0x1c))+d1;
    b2=*(DWORD *)(LM+0X28);    
    a1=((s1^d1)^b1)+0x4BDECFA9;
    d2=d2+b2+a1;
    d2=((d2<<0xb)|(d2>>0x15))+b1;
    b2=*(DWORD *)(LM+0X34);    
    a1=(d2^d1)^b1;
    s1=s1+b2+0xF6BB4B60+a1;
    s1=((s1<<0x10)|(s1>>0x10))+d2;
    b2=*(DWORD *)(LM+0X40);    
    a1=(d2^s1);
    d1=d1+b2+0xBEBFBC70+(b1^a1);
    d1=((d1<<0x17)|(d1>>0x9))+s1;
    b2=*(DWORD *)(LM+0X4c);    
    b1=b1+b2+0x289B7EC6+(d1^a1);
    b1=((b1<<0x4)|(b1>>0x1c))+d1;
    b2=*(DWORD *)(LM+0X18);    
    a1=((s1^d1)^b1)+0xEAA127FA;
    d2=d2+b2+a1;
    d2=((d2<<0xb)|(d2>>0x15))+b1;
    b2=*(DWORD *)(LM+0X24);    
    a1=(d2^d1)^b1;
    s1=s1+b2+0xD4EF3085+a1;
    s1=((s1<<0x10)|(s1>>0x10))+d2;
    b2=*(DWORD *)(LM+0X30);    
    a1=d2^s1;
    d1=d1+b2+0x4881D05+(b1^a1);
    d1=((d1<<0x17)|(d1>>0x9))+s1;
    b2=d1^a1;
    a1=*(DWORD *)(LM+0X3c)+0xD9D4D039;    
    b1=b1+b2+a1;
    b1=((b1<<0x4)|(b1>>0x1c))+d1;
    b2=*(DWORD *)(LM+0X48);
    a1=((s1^d1)^b1)+0xE6DB99E5;
    d2=d2+b2+a1;
    d2=((d2<<0xb)|(d2>>0x15))+b1;
    b2=*(DWORD *)(LM+0X54);
    a1=((d2^d1)^b1);
    s1=s1+b2+0x1FA27CF8+a1;
    s1=((s1<<0x10)|(s1>>0x10))+d2;
    b2=*(DWORD *)(LM+0X20);
    a1=((d2^s1)^b1);
    d1=d1+b2+0xC4AC5665+a1;
    d1=((d1<<0x17)|(d1>>0x9))+s1;
    //第4轮
    b2=*(DWORD *)(LM+0X18);
    a1=(((d2^0xFFFFFFFF)|d1)^s1)+0xF4292244;
    b1=b1+b2+a1;
    b1=((b1<<0x6)|(b1>>0x1a))+d1;
    b2=*(DWORD *)(LM+0X34);
    a1=(((s1^0xFFFFFFFF)|b1)^d1)+0x432AFF97;
    d2=d2+b2+a1;
    d2=((d2<<0xa)|(d2>>0x16))+b1;
    b2=*(DWORD *)(LM+0X50);
    a1=(((d1^0xFFFFFFFF)|d2)^b1)+0xAB9423A7;
    s1=s1+b2+a1;
    s1=((s1<<0xf)|(s1>>0x11))+d2;
    b2=*(DWORD *)(LM+0X2c);
    a1=(((b1^0xFFFFFFFF)|s1)^d2);
    d1=d1+b2+0xFC93A039+a1;
    d1=((d1<<0x15)|(d1>>0xb))+s1;
    b2=*(DWORD *)(LM+0X48);
    a1=(((d2^0xFFFFFFFF)|d1)^s1)+0x655B59C3;
    b1=b1+b2+a1;
    b1=((b1<<0x6)|(b1>>0x1a))+d1;
    b2=*(DWORD *)(LM+0X24);
    a1=(((s1^0xFFFFFFFF)|b1)^d1)+0x8F0CCC92;
    d2=d2+b2+a1;
    d2=((d2<<0xa)|(d2>>0x16))+b1;
    b2=*(DWORD *)(LM+0X40);
    a1=(((d1^0xFFFFFFFF)|d2)^b1)+0xFFEFF47D;
    s1=s1+b2+a1;
    s1=((s1<<0xf)|(s1>>0x11))+d2;
    b2=*(DWORD *)(LM+0X1c);
    a1=(((b1^0xFFFFFFFF)|s1)^d2)+0x85845DD1;
    d1=d1+b2+a1;
    d1=((d1<<0x15)|(d1>>0xb))+s1;
    b2=*(DWORD *)(LM+0X38);
    a1=(((d2^0xFFFFFFFF)|d1)^s1)+0x6FA87E4F;
    b1=b1+b2+a1;
    b1=((b1<<0x6)|(b1>>0x1a))+d1;
    b2=*(DWORD *)(LM+0X54);
    a1=(((s1^0xFFFFFFFF)|b1)^d1)+0xFE2CE6E0;
    d2=d2+b2+a1;
    d2=((d2<<0xa)|(d2>>0x16))+b1;
    b2=*(DWORD *)(LM+0X30);
    a1=(((d1^0xFFFFFFFF)|d2)^b1)+0xA3014314;
    s1=s1+b2+a1;
    s1=((s1<<0xf)|(s1>>0x11))+d2;
    b2=*(DWORD *)(LM+0X4c);
    a1=(((b1^0xFFFFFFFF)|s1)^d2)+0x4E0811A1;
    d1=d1+b2+a1;
    d1=((d1<<0x15)|(d1>>0xb))+s1;
    b2=*(DWORD *)(LM+0X28);
    a1=(((d2^0xFFFFFFFF)|d1)^s1)+0xF7537E82;
    b1=b1+b2+a1;
    b1=((b1<<0x6)|(b1>>0x1a))+d1;
    b2=*(DWORD *)(LM+0X44);
    a1=(((s1^0xFFFFFFFF)|b1)^d1)+0xBD3AF235;
    d2=d2+b2+a1;
    d2=((d2<<0xa)|(d2>>0x16))+b1;
    b2=*(DWORD *)(LM+0X20);
    a1=(((d1^0xFFFFFFFF)|d2)^b1)+0x2AD7D2BB;
    s1=s1+b2+a1;
    s1=((s1<<0xf)|(s1>>0x11))+d2;
    b2=*(DWORD *)(LM+0X3c);
    a1=(((b1^0xFFFFFFFF)|s1)^d2)+0xEB86D391;
    d1=d1+b2+a1;
    d1=((d1<<0x15)|(d1>>0xb))+s1;

    b2=*(DWORD *)(LM+0X8);
    b1=b1+b2;
    b2=*(DWORD *)(LM+0Xc);
    d1=d1+b2;
    b2=*(DWORD *)(LM+0X10);
    s1=s1+b2;
    b2=*(DWORD *)(LM+0X14);
    d2=d2+b2;
    *(DWORD *)(LM+0X8)=b1;
    *(DWORD *)(LM+0Xc)=d1;
    *(DWORD *)(LM+0X10)=s1;
    *(DWORD *)(LM+0X14)=d2;
} 