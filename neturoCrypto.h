#ifndef BLASTSOCK_NETUROCRYPTO_H
#define BLASTSOCK_NETUROCRYPTO_H

// neturoCrypto.h
// aes 암호화해준다!
#include "./cryptopp561/aes.h"
#include "./cryptopp561/randpool.h"
#include "./cryptopp561/modes.h"

#include <string>
//#include <iostream.h>
#include <iostream>

#include <time.h>
#include <windows.h>


USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

class neturoCrypto  
{
public:
	neturoCrypto();
	virtual ~neturoCrypto();
	void GenerateRSAKey(unsigned int keyLength, char *privateKey_char, char *publicKey_char);
	
	void InitAESKey();
	
	void AESEncryptString(char *ciphertext, const char *plaintext, unsigned int length);
	void AESDecryptString(char *plaintext, const char *ciphertext, unsigned int length);

	void SetAESKey(byte *HexEncodedKey);
	void SetAESiv(byte *HexEncodediv);
	
	byte *GetHexDecodedKey();
	byte *GetHexDecodediv();
	byte *GetHexEncodedKey();
	byte *GetHexEncodediv();

	string RSAEncryptString(const char *publicKey, const char *message);
	string RSADecryptString(const char *privateKey, const char *ciphertext);

	RandomPool & GlobalRNG();
private:
//	CFB_Mode<AES >::Encryption	m_cfbEncryption;
	byte neturoAESKey[AES::DEFAULT_KEYLENGTH]; 
	byte neturoAESiv[AES::BLOCKSIZE];
	byte hexEncodedAESKey[AES::DEFAULT_KEYLENGTH*2];
	byte hexEncodedAESiv[AES::BLOCKSIZE*2];
};

#endif // #ifndef BLASTSOCK_NETUROCRYPTO_H