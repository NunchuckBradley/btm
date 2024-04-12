#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <sstream>
#include <iostream>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

class Crypto {
public:
    static std::string base64_encode(const std::string &s);
    static std::string base32_decode(const std::string &s);

    static std::string decToHex(int dec);
    static unsigned int stringHexToInt(std::string str);
    static unsigned int charHexToInt(const char hex);
    static int getBitLength(int x);
    static void hexStringToCharBinary(unsigned char* dest, std::string src, int size);
    static void hexStringToCryptoByte(CryptoPP::byte* dest, std::string* src, int size);
    static void hexStringByteSeperate(CryptoPP::byte* dest, std::string* src);
    static std::string hexdump(unsigned char* data, int len);

    static void hexStringToCharBinaryVector(std::vector<unsigned char>* dest, std::string* src, int size);
    static std::string getHash(std::string headerString);
    static void getHashFromChar(unsigned char* headerData, CryptoPP::byte* dest);
    static void byte_swap(unsigned char* data, int len);
    static unsigned int decToHexLittleEndian(unsigned int decimal);

    static std::string hexStringLittleEndian(std::string bigend);
//    static unsigned int hexStringLittleEndian(std::string src);

    static bool compareByteArray(CryptoPP::byte* challenger, CryptoPP::byte* defender);
    static void hexStringToByte(CryptoPP::byte* dest, std::string* src);

    static std::string HexStr(uint8_t* m_data);
    static bool IsSpace(const char space);
};

#endif // CRYPTO_H
