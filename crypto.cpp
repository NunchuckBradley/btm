#include "crypto.h"
#include "uint_custom.h"

#include <cryptopp/base64.h>
#include <cryptopp/base32.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>


std::string Crypto::base64_encode(const std::string &s)
{
    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i=0,ix=0,leng = s.length();
    std::stringstream q;

    for(i=0,ix=leng - leng%3; i<ix; i+=3)
    {
        q<< base64_chars[ (s[i] & 0xfc) >> 2 ];
        q<< base64_chars[ ((s[i] & 0x03) << 4) + ((s[i+1] & 0xf0) >> 4)  ];
        q<< base64_chars[ ((s[i+1] & 0x0f) << 2) + ((s[i+2] & 0xc0) >> 6)  ];
        q<< base64_chars[ s[i+2] & 0x3f ];
    }
    if (ix<leng)
    {
        q<< base64_chars[ (s[ix] & 0xfc) >> 2 ];
        q<< base64_chars[ ((s[ix] & 0x03) << 4) + (ix+1<leng ? (s[ix+1] & 0xf0) >> 4 : 0)];
        q<< (ix+1<leng ? base64_chars[ ((s[ix+1] & 0x0f) << 2) ] : '=');
        q<< '=';
    }
    return q.str();
}

std::string Crypto::base32_decode(const std::string &s) {
    // bc1 qfc7fameteuguetm0kfzypnvf2ju6wppd vj6tkc
    const std::string base32_chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    const unsigned int bits = s.size()*5 + (8 - (s.size()*5) % 8);

    std::cout << "output bytes: " << bits/8 << std::endl;

    uint8_t asBytes[bits/8];

    int i = 0;
    int bytePos = bits/8 - 1;
    while(i < s.size()) {
        int backs = s.size() - 1 - i;
        int val = base32_chars.find(s[backs]);
    }

    return "";


//    unsigned int output[bits/8];

//    int i = s.size()-1;
//    while (i >= 0) {
//        int pos = base32_chars.find(s[i]);
//        std::cout << "loop: " << i << "  pos: " << pos << std::endl;
//        memcpy(&output+(i*5), &pos, 5);
//        i--;
//    }

//    std::cout << "writing finals" << std::endl;

//    std::string final;
//    int o = 0;
//    while (o < sizeof(output)) {
//        std::cout << o << " : " << output[o] << " : " << Crypto::decToHex(output[o]) << std::endl;
//        final += Crypto::decToHex(output[o]);
//        o++;
//    }


//    // Decoder
//    int lookup[256];
//    const CryptoPP::byte ALPHABET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
//    CryptoPP::Base32HexDecoder::InitializeDecodingLookupArray(lookup, ALPHABET, 64, false);

//    CryptoPP::Base32HexDecoder decoder;
//    CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::DecodingLookupArray(),(const int *)lookup);
//    decoder.IsolatedInitialize(params);
//    decoder.Put( (CryptoPP::byte*)s.data(), s.size() );
//    decoder.MessageEnd();

//    std::string decoded;
//    CryptoPP::word64 size = decoder.MaxRetrievable();
//    if(size && size <= SIZE_MAX)
//    {
//        decoded.resize(size);
//        decoder.Get((CryptoPP::byte*)&decoded[0], decoded.size());
//    }

//    size_t i=0,ix=0,leng = s.length();
//    std::stringstream q;

//    for(i=0,ix=leng - leng%3; i<ix; i+=3)
//    {
//        q<< base32_chars[ (s[i] & 0xfc) >> 2 ]; // 1111 1100
//        q<< base32_chars[ ((s[i] & 0x03) << 4) + ((s[i+1] & 0xf0) >> 4)  ]; // 0000 0011, 1111 0000
//        q<< base32_chars[ ((s[i+1] & 0x0f) << 2) + ((s[i+2] & 0xc0) >> 6)  ]; // 0000 1111, 1100 000
//        q<< base32_chars[ s[i+2] & 0x3f ]; // 0011 1111
//    }
//    if (ix<leng)
//    {
//        q<< base32_chars[ (s[ix] & 0xfc) >> 2 ];
//        q<< base32_chars[ ((s[ix] & 0x03) << 4) + (ix+1<leng ? (s[ix+1] & 0xf0) >> 4 : 0)];
//        q<< (ix+1<leng ? base32_chars[ ((s[ix+1] & 0x0f) << 2) ] : '=');
//        q<< '=';
//    }
//    return q.str();
}

std::string bitsToHex(int dec) {
    switch(dec) {
        case 15:
        return "f";
        break;
        case 14:
        return "e";
        break;
        case 13:
        return "d";
        break;
        case 12:
        return "c";
        break;
        case 11:
        return "b";
        break;
        case 10:
        return "a";
        break;
        case 9:
        return "9";
        break;
        case 8:
        return "8";
        break;
        case 7:
        return "7";
        break;
        case 6:
        return "6";
        break;
        case 5:
        return "5";
        break;
        case 4:
        return "4";
        break;
        case 3:
        return "3";
        break;
        case 2:
        return "2";
        break;
        case 1:
        return "1";
        break;
        default:
        return "0";
    }
}

std::string Crypto::decToHex(int dec) {
    std::stringstream ss;
    ss<< std::hex << dec; // int decimal_value
    std::string res ( ss.str() );
    return res;

    // this method faster
//    std::string out;
//    bool leadingZeros = true;
//    for(int i =  sizeof(dec)-1; i >= 0; i--) {
//        int byte = (dec >> (i << 3)) & 0xff;
//        if(byte == 0 && leadingZeros) {
//            continue;
//        }
//        leadingZeros = false;
//        int r = byte % 16;
//        int l = byte >> 4;
//        out += bitsToHex(l);
//        out += bitsToHex(r);
//    }
//    return out;
}

unsigned int Crypto::stringHexToInt(std::string str) {
    unsigned int x;
    std::stringstream ss;
    ss << std::hex << str;
    ss >> x;
    return x;
}

int Crypto::getBitLength(int x) {
    unsigned int bits, var = (x < 0) ? -x : x;
    for(bits = 0; var != 0; ++bits) var >>= 1;
    return bits;
}

void Crypto::hexStringToCharBinary(unsigned char* dest, std::string src, int size) {
//      std::cout << "somewhere failing?" << std::endl;
    const char *srcy = src.c_str();
    char buf[3];
    buf[2] = 0;
    for(int i = 0; size > i ; i++) {
//          std::cout << "loop: " << i << std::endl;
//          buf[0] = srcy[i*2];
//          buf[1] = srcy[(i*2)+1];
//          dest[i] = (unsigned char)strtol(buf, NULL, 16);
        dest[i] = Crypto::stringHexToInt(src.substr(i*2, 2));
    }
}

void Crypto::hexStringToCryptoByte(CryptoPP::byte* dest, std::string* src, int size) {
    const char *srcy = src->c_str();
    char buf[3];
    buf[2] = 0;
    for(int i = 0; size > i ; i++) {
        std::string destination = src->substr(i*2, 2);
        dest[i] = Crypto::stringHexToInt(destination);
//          CryptoPP::StringSource ss(srcy, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(destination)));
//          const CryptoPP::byte* result = (const CryptoPP::byte*) destination.data();
//          dest[i] = *result;
    }
}

void Crypto::hexStringByteSeperate(CryptoPP::byte* dest, std::string* src) {
    const char *srcy = src->c_str();
    for(int i = 0; src->length() > i ; i++) {
        dest[i] = *src[i].c_str();
    }
}

std::string Crypto::hexdump(unsigned char* data, int len)
{
    std::string tmp;
    int c;

    c=0;
    while(c < len)
    {
          tmp += Crypto::decToHex(data[c++]);
//        printf("%.2x", data[c++]);
    }
      return tmp;
//    printf("\n");
}


std::string Crypto::hexStringLittleEndian(std::string bigend) {
    int size = bigend.length();
    std::string tmp = bigend;
    bigend.clear();

    std::string littlee;

    for (int i = 0; size/2 > i; i++) {
        littlee += tmp[ size-(i*2+2) ];
        littlee += tmp[ size-(i*2+1) ];
    }
    return littlee;
//      *bigend = littlee;
}

void Crypto::hexStringToCharBinaryVector(std::vector<unsigned char>* dest, std::string* src, int size) {
    const char *srcy = src->c_str();
    char buf[3];
    buf[2] = 0;
    for(int i = 0; size > i ; i++) {
//          buf[0] = srcy[i*2];
//          buf[1] = srcy[(i*2)+1];
//          dest[i] = (unsigned char)strtol(buf, NULL, 16);
        dest->push_back( Crypto::stringHexToInt(src->substr(i*2, 2)) );
    }
}

std::string Crypto::getHash(std::string headerString) {
    // Convert hex string to byte array
    std::string headerData;
    CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(headerData));
    decoder.Put((CryptoPP::byte*)headerString.data(), headerString.size());
    decoder.MessageEnd();

    // Hash the byte array twice
    CryptoPP::SHA256 hasher;

    CryptoPP::byte hash1[CryptoPP::SHA256::DIGESTSIZE];
    hasher.CalculateDigest(hash1, (CryptoPP::byte*)headerData.data(), headerData.size());

    CryptoPP::byte hash2[CryptoPP::SHA256::DIGESTSIZE];
    hasher.CalculateDigest(hash2, hash1, sizeof(hash1));

    // Convert result to hex string
    std::string hashString;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashString));
    encoder.Put(hash2, sizeof(hash2));
    encoder.MessageEnd();

    // Print the hash
    return hashString;
    return Crypto::hexStringLittleEndian(hashString);
}

void Crypto::getHashFromChar(unsigned char* headerData, CryptoPP::byte* dest) {
    // Convert hex string to byte array
//      std::string headerData;
//      CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(headerData));
//      decoder.Put((CryptoPP::byte*)headerString.data(), headerString.size());
//      decoder.MessageEnd();

    // Hash the byte array twice
    CryptoPP::SHA256 hasher;

    CryptoPP::byte hash1[CryptoPP::SHA256::DIGESTSIZE];
    hasher.CalculateDigest(hash1, headerData, sizeof(headerData));

    CryptoPP::byte hash2[CryptoPP::SHA256::DIGESTSIZE];
    hasher.CalculateDigest(hash2, hash1, sizeof(hash1));

    dest = hash2;
//      return hash2;

//      CryptoPP::byte tmp;
//      CryptoPP::byte* tmptmp = &tmp;

//      std::cout << "printing hash" << std::endl;
//      int i = 0;
//      while (i < 32) {
//          std::cout << Crypto::decToHex(hash2[i]);
//          tmptmp[i] = hash2[i];
//          i++;
//      }
//      std::cout << std::endl;

//      return tmp;

//      // Convert result to hex string
//      std::string hashString;
//      CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashString));
//      encoder.Put(hash2, sizeof(hash2));
//      encoder.MessageEnd();
//      std::cout << hashString << std::endl;

//      // Print the hash
////      return hashString;
//      return Crypto::hexStringLittleEndian(&hashString);
}

void Crypto::byte_swap(unsigned char* data, int len) {
    int c;
    unsigned char tmp[len];

    c=0;
    while(c<len)
    {
        tmp[c] = data[len-(c+1)];
        c++;
    }

    c=0;
    while(c<len)
    {
        data[c] = tmp[c];
        c++;
    }
}

unsigned int Crypto::decToHexLittleEndian(unsigned int decimal) {
    std::string stmp = Crypto::decToHex(decimal);
    return Crypto::stringHexToInt(stmp);
}

//unsigned int Crypto::hexStringLittleEndian(std::string src) {
//    std::string stmp = src;
//    return Crypto::stringHexToInt(stmp);
//}

bool Crypto::compareByteArray(CryptoPP::byte* challenger, CryptoPP::byte* defender) {
  for(int i = 0; i < 32; i++) {
      int ci = 31 - i;
      int di = i;
//        std::cout << "comparing: " << challenger[ci] << " : " << defender[di] << std::endl;
      if (challenger[ci] == defender[di]) {
          continue;
      } else if (challenger[ci] > defender[di]){
          return false;
      } else if (challenger[ci] < defender[di]) {
          return true;
      }
  }
  return false;
}

void Crypto::hexStringToByte(CryptoPP::byte* dest, std::string* src) {
    std::string headerData;
    CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(headerData));
    decoder.Put((CryptoPP::byte*)src->data(), src->size());
    decoder.MessageEnd();
    dest = (CryptoPP::byte*)headerData.data();
}

// uint256 stuff
std::string Crypto::HexStr(uint8_t* m_data) {
    std::string out;
    for(int i = 0; i < sizeof(m_data); i++) {
        out += Crypto::decToHex(m_data[i]);
    }
    return out;
}

bool Crypto::IsSpace(const char space) {
    if (space == '0' || space == ' ') {
        return true;
    }
    return false;
}

unsigned int Crypto::charHexToInt(const char hex) {
//    unsigned int x;
//    std::stringstream ss;
//    ss << std::hex << hex;
//    ss >> x;
//    return x;
    switch(hex){
        case 'F'|'f':
        return 15;
        break;
        case 'E'|'e':
        return 14;
        break;
        case 'D'|'d':
        return 13;
        break;
        case 'C'|'c':
        return 12;
        break;
        case 'B'|'b':
        return 11;
        break;
        case 'A'|'a':
        return 10;
        break;
        case '9':
        return 9;
        break;
        case '8':
        return 8;
        break;
        case '7':
        return 7;
        break;
        case '6':
        return 6;
        break;
        case '5':
        return 5;
        break;
        case '4':
        return 4;
        break;
        case '3':
        return 3;
        break;
        case '2':
        return 2;
        break;
        case '1':
        return 1;
        break;
        default:
        return 0;
    }
}
