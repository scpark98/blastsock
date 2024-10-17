// vncauth.h from tightvnc
// Revision 1.2 / Tue Aug 14 15:53:03 2001 UTC by const 
// Branch: MAIN 
		
/* 
 * neturoauth.h - describes the functions provided by the neturoauth library.
 */

#define MAX_ID_LEN 12 // 128 -> 12
#define MAXPWLEN 16 // 48 -> 16
#define CHALLENGESIZE 16

extern int neturoEncryptPasswd(char *passwd, char *fname);
extern char *neturoDecryptPasswd(char *fname);
extern void neturoRandomBytes(unsigned char *bytes);
extern void neturoEncryptBytes(unsigned char *bytes, const char *passwd);
