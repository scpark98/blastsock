// vncauth.c from tightvnc
// Revision 1.4 / Fri Aug 30 13:19:05 2002 UTC by const_k 
// Branch: MAIN 

/*
 *  Functions for NETUROWV password management and authentication.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "neturoauth.h"
#include "d3des.h"

/*
 *   We use a fixed key to store passwords, since we assume that our local
 *   file system is secure but nonetheless don't want to store passwords
 *   as plaintext.
 */

static unsigned char s_fixedkey[8] = {24,25,132,9,42,56,43,2};

/*
 *   Encrypt a password and store it in a file.
 */
int
neturoEncryptPasswd(char *passwd, char *encryptedPasswd)
{
    int i;

    /* pad password with nulls */

    for (i = 0; i < MAXPWLEN; i++) {
	if (i < (int)strlen(passwd)) {
	    encryptedPasswd[i] = passwd[i];
	} else {
	    encryptedPasswd[i] = 0;
	}
    }

    /* Do encryption in-place - this way we overwrite our copy of the plaintext
       password */

    deskey(s_fixedkey, EN0);
    //des(encryptedPasswd, encryptedPasswd); - by scyrie

	// by scyrie
	for (i = 0; i < MAXPWLEN; i += 8) {
	des(encryptedPasswd+i, encryptedPasswd+i);
    }
	// ~by scyrie
    return 8;
}

/*
 *   Decrypt a password.  Returns a pointer to a newly allocated
 *   string containing the password or a null pointer if the password could
 *   not be retrieved for some reason.
 */
char *
neturoDecryptPasswd(char *inouttext)
{
	int i;
    unsigned char *passwd = (unsigned char *)malloc(MAXPWLEN+1);

    deskey(s_fixedkey, DE1);
//    des(inouttext, passwd); - by scyrie

	for (i = 0; i < MAXPWLEN; i += 8) {
	des(inouttext+i, passwd+i);
    }

    passwd[MAXPWLEN] = 0;

    return (char *)passwd;
}

/*
 *   Generate a set of random bytes for use in challenge-response authentication.
 */
void
neturoRandomBytes(unsigned char *where) {
  int i;
  unsigned int seed = (unsigned int) time(0);

  srand(seed);
  for (i=0; i < CHALLENGESIZE; i++) {
    where[i] = (unsigned char)(rand() & 255);    
  }
}

/*
 *   Encrypt some bytes in memory using a password.
 */
void
neturoEncryptBytes(unsigned char *where, const char *passwd)
{
    unsigned char key[MAXPWLEN];
    int i;

    /* key is simply password padded with nulls */

    for (i = 0; i < MAXPWLEN; i++) {
	if (i < (int)strlen(passwd)) {
	    key[i] = passwd[i];
	} else {
	    key[i] = 0;
	}
    }

    deskey(key, EN0);

    for (i = 0; i < CHALLENGESIZE; i += 8) {
	des(where+i, where+i);
    }
}
