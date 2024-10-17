// vncPasswd.h from tightvnc
// Revision 1.3
// Tue Aug 14 15:53:02 2001 UTC by const 
// Branch: MAIN
		
// neturoPassword

// This header provides helpers for handling encrypted password data.
// The password handling routines found in neturoauth.h should not be used directly

class neturoPassword;

#if (!defined(_NETURO_NETUROWVPASSWD))
#define _NETURO_NETUROWVPASSWD

//#include "stdhdrs.h"
extern "C" {
#include "neturoauth.h"
}

// Password handling helper class
class neturoPassword
{
public:

    // Password decryptor!
    class ToText
    {
    public:
	inline ToText(const char encrypted[MAXPWLEN])
	{
	    //nlog.Print(LL_INTINFO, NLOG("PASSWD : ToText called\n"));
	    plaintext = neturoDecryptPasswd((char *)encrypted);
	}
	inline ~ToText()
	{
	    if (plaintext != NULL)
	    {
		ZeroMemory(plaintext, strlen(plaintext));
		free(plaintext);
	    }
	}
	inline operator const char*() const {return plaintext;};
    private:
	char *plaintext;
    };

    class FromText
    {
    public:
	inline FromText(char *unencrypted)
	{
	    //nlog.Print(LL_INTINFO, NLOG("PASSWD : FromText called\n"));
	    neturoEncryptPasswd(unencrypted, encrypted);
	    ZeroMemory(unencrypted, strlen(unencrypted));
	}
	inline ~FromText()
	{
	}
	inline operator const char*() const {return encrypted;};
    private:
	char encrypted[MAXPWLEN];
    };

    class FromClear
    {
    public:
	inline FromClear()
	{
	    //nlog.Print(LL_INTINFO, NLOG("PASSWD : FromClear called\n"));
	    neturoEncryptPasswd("", encrypted);
	}
	inline ~FromClear()
	{
	}
	inline operator const char*() const {return encrypted;};
    private:
	char encrypted[MAXPWLEN];
    };
};

#endif
