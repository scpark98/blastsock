// neturoCrypto.cpp: implementation of the neturoCrypto class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "neturoCrypto.h"

#include "./cryptopp/hex.h"
#include "./cryptopp/rsa.h"
#include "./cryptopp/osrng.h"
#include "./cryptopp/sha.h"

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

neturoCrypto::neturoCrypto()
{

}

neturoCrypto::~neturoCrypto()
{

}
 
RandomPool & neturoCrypto::GlobalRNG()
{
	static RandomPool randomPool;
	return randomPool;
}

void neturoCrypto::GenerateRSAKey(unsigned int keyLength, char *privateKey_char, char *publicKey_char)
{
	/*AutoSeededRandomPool randPool;
	
	string privateKey;
	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	HexEncoder privKey;	//(new StringSinkTemplate<std::string>(privateKey));
	priv.DEREncode(privKey);
	privKey.MessageEnd();	
	privKey.Get((byte *)privateKey_char, 1300);

	//string publicKey = publicKey_char;
	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubKey;
	pub.DEREncode(pubKey);
	pubKey.MessageEnd();
	pubKey.Get((byte *)publicKey_char, 320);*/

	AutoSeededRandomPool randPool;

	// 1. RSA 키 생성
	RSA::PrivateKey privateKey;
	privateKey.GenerateRandomWithKeySize(randPool, keyLength);

	RSA::PublicKey publicKey(privateKey);

	// 2. 개인 키를 Hex 인코딩하여 저장
	string privateKeyStr;
	HexEncoder privEncoder(new StringSink(privateKeyStr));
	privateKey.DEREncode(privEncoder);
	privEncoder.MessageEnd();

	strncpy(privateKey_char, privateKeyStr.c_str(), privateKeyStr.size());
	privateKey_char[privateKeyStr.size()] = '\0'; // 문자열 종료 추가

	// 3. 공개 키를 Hex 인코딩하여 저장
	string publicKeyStr;
	HexEncoder pubEncoder(new StringSink(publicKeyStr));
	publicKey.DEREncode(pubEncoder);
	pubEncoder.MessageEnd();

	strncpy(publicKey_char, publicKeyStr.c_str(), publicKeyStr.size());
	publicKey_char[publicKeyStr.size()] = '\0'; // 문자열 종료 추가
}

string neturoCrypto::RSAEncryptString(const char *publicKey, const char *message)
{
	try
	{
		StringSource pubKey(publicKey, true, new HexDecoder);
		//FileSource pubFile(pubFilename, true, new HexDecoder);
		RSAES_OAEP_SHA_Encryptor pub(pubKey);

		AutoSeededRandomPool randPool;
	
		string result;
		StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
		return result;
	}
	catch(...)
	{
		// 에러처리. 안한다.ㅡ.ㅡ:
		string result;
		return result;
	}
}

string neturoCrypto::RSADecryptString(const char *privateKey, const char *ciphertext)
{
	StringSource privKey(privateKey, true, new HexDecoder);
	//FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privKey);

	string result;
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
	return result;
}

void neturoCrypto::InitAESKey()
{
	ZeroMemory(neturoAESKey, AES::DEFAULT_KEYLENGTH);
	ZeroMemory(neturoAESiv, AES::BLOCKSIZE);
	AutoSeededRandomPool rng;
	//byte randomBytes[AES::DEFAULT_KEYLENGTH];
	rng.GenerateBlock((CryptoPP::byte *)neturoAESKey, AES::DEFAULT_KEYLENGTH);
	rng.GenerateBlock((CryptoPP::byte *)neturoAESiv, AES::BLOCKSIZE);
	//strncpy((char *)neturoAESiv, "12345678901234567890", AES::BLOCKSIZE);
}

void neturoCrypto::AESEncryptString(char *ciphertext, const char *plaintext, unsigned int length)
{
	CFB_Mode<AES >::Encryption cfbEncryption(neturoAESKey, AES::DEFAULT_KEYLENGTH, neturoAESiv);
	cfbEncryption.ProcessData((CryptoPP::byte *)ciphertext, (CryptoPP::byte *)plaintext, length);
}

void neturoCrypto::AESDecryptString(char *plaintext, const char *ciphertext, unsigned int length)
{
	CFB_Mode<AES >::Decryption cfbDecryption(neturoAESKey, AES::DEFAULT_KEYLENGTH, neturoAESiv);
    cfbDecryption.ProcessData((CryptoPP::byte *)plaintext, (CryptoPP::byte *)ciphertext, length);
}

CryptoPP::byte * neturoCrypto::GetHexDecodedKey()
{
	return neturoAESKey;
}

CryptoPP::byte * neturoCrypto::GetHexDecodediv()
{
	return neturoAESiv;
}

void neturoCrypto::SetAESKey(CryptoPP::byte *HexEncodedKey)
{
	ZeroMemory(neturoAESKey, AES::DEFAULT_KEYLENGTH);

	HexDecoder hexDecoder;
	hexDecoder.Put(HexEncodedKey,AES::DEFAULT_KEYLENGTH*2);
	hexDecoder.MessageEnd();
	hexDecoder.Get(neturoAESKey,AES::DEFAULT_KEYLENGTH);

	return;
}

void neturoCrypto::SetAESiv(CryptoPP::byte *HexEncodediv)
{
	ZeroMemory(neturoAESiv, AES::BLOCKSIZE);

	HexDecoder hexDecoder;
	hexDecoder.Put(HexEncodediv,AES::BLOCKSIZE*2);
	hexDecoder.MessageEnd();
	hexDecoder.Get(neturoAESiv,AES::BLOCKSIZE*2);

	return;
}

CryptoPP::byte * neturoCrypto::GetHexEncodedKey()
{
	ZeroMemory(hexEncodedAESKey, AES::DEFAULT_KEYLENGTH*2);

	HexEncoder hexEncoder;
	hexEncoder.Put(neturoAESKey,AES::DEFAULT_KEYLENGTH);
	hexEncoder.MessageEnd();
	hexEncoder.Get(hexEncodedAESKey,AES::DEFAULT_KEYLENGTH*2);
	return hexEncodedAESKey;
}

CryptoPP::byte * neturoCrypto::GetHexEncodediv()
{
	ZeroMemory(hexEncodedAESiv, AES::BLOCKSIZE*2);

	HexEncoder hexEncoder;
	hexEncoder.Put(neturoAESiv,AES::BLOCKSIZE);
	hexEncoder.MessageEnd();
	hexEncoder.Get(hexEncodedAESiv,AES::BLOCKSIZE*2);
	return hexEncodedAESiv;
}

