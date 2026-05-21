// vncauth.h from tightvnc
// Revision 1.2 / Tue Aug 14 15:53:03 2001 UTC by const 
// Branch: MAIN 
		
/* 
 * neturoauth.h - describes the functions provided by the neturoauth library.
 */

// 20170809 [프록시 ID/PW 자리 수 문제] : 프록시 ID/PW 자리수를 충분이 늘려준다 (ID : 12 -> 128, PW 16 -> 48)
//                                        기존에 PW 자리수가 16으로 되어 있어(레지스트리에는 48) RegQueryValueEx(...,"ProxyPW",...)에서 234 오류 발생
#define MAX_ID_LEN 256 // 128 -> 12 -> 128
#define MAXPWLEN 256 // 48 -> 16 -> 48

#define CHALLENGESIZE 16

extern int neturoEncryptPasswd(const char *passwd, char *fname);
extern char *neturoDecryptPasswd(const char *fname);
extern void neturoRandomBytes(unsigned char *bytes);
extern void neturoEncryptBytes(unsigned char *bytes, const char *passwd);
