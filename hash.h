#ifndef HASH_H
#define HASH_H

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include "uint_custom.h"
//#include "sha256.h"

class Hashing {
public:
    static uint256<256> calcHash(unsigned char *headerData, int length)
    {
//        Crypto::hexdump(headerData, 80);
//        std::cout<<std::endl;

        // 5f6ad7cc6c5866aa5b84d087ca84337eaee2978d0d9b7000e46c2b215c2256fd
        // 5f6ad7cc6c5866aa5b84d087ca84337eaee2978d0d9b7000e46c2b215c2256fd
//        unsigned char hashed;
//        sha256( &hashed, headerData, 80 );
//        sha256( &hashed, &hashed, SHA256::DIGEST_SIZE );

//        Crypto::hexdump(&hashed, SHA256::DIGEST_SIZE);

//        std::cout<<std::endl;

        CryptoPP::SHA256 hasher;

        CryptoPP::byte hash1[CryptoPP::SHA256::DIGESTSIZE];
        hasher.CalculateDigest(hash1, headerData, length);

        CryptoPP::byte hash2[CryptoPP::SHA256::DIGESTSIZE];
        hasher.CalculateDigest(hash2, hash1, sizeof(hash1));

        uint256<256> tmp;
        tmp = hash2;
        return tmp;
    }
    static uint256<256> calcMerklHash(uint256<512>* combined, int length)
    {
        unsigned char combinedAsChar[length] ;
        memset(&combinedAsChar, 0, length);
        memcpy(&combinedAsChar, combined, length);

        CryptoPP::SHA256 hasher;

        CryptoPP::byte hash1[CryptoPP::SHA256::DIGESTSIZE];
        hasher.CalculateDigest(hash1, combinedAsChar, length);

        CryptoPP::byte hash2[CryptoPP::SHA256::DIGESTSIZE];
        hasher.CalculateDigest(hash2, hash1, sizeof(hash1));

        uint256<256> tmpu;
        tmpu = hash2;

        return tmpu;
    }

//    static unsigned int leftRotate(unsigned int n, unsigned int d, int int_bits)
//    {

//        /* In n<<d, last d bits are 0. To
//         put first 3 bits of n at
//        last, do bitwise or of n<<d
//        with n >>(INT_BITS - d) */
//        return (n << d)|(n >> (int_bits - d));
//    }
//    /*Function to right rotate n by d bits*/
//    static unsigned int rightRotate(unsigned int n, unsigned int d, int int_bits)
//    {
//        /* In n>>d, first d bits are 0.
//        To put last 3 bits of at
//        first, do bitwise or of n>>d
//        with n <<(INT_BITS - d) */
//        return (n >> d)|(n << (int_bits - d));
//    }

//    static uint256<256> sha256header(unsigned char* input, int length) {
//        uint256<256> hashed = sha256AlgorithmUint256Input(input, length);

////        std::cout << "hashed: " << hashed.getHex(false) << std::endl;
////        std::cout << "expected: 125180087704c9c69cd09939aa92129b1f5e90df25cbfe6bee598637461678b2" << std::endl;

//        unsigned char digest[32];
//        memcpy(&digest, &hashed, 32);

//        uint256<256> hashed2 = sha256AlgorithmUint256Input(digest, 32);
//        return hashed2;
//    }

//    static uint256<256> sha256AlgorithmUint256Input(unsigned char* input, int length) {
//        // attempting to create it myself with https://qvault.io/2020/07/08/how-sha-2-works-step-by-step-sha-256/

////        unsigned char newinput[11] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64};
////        length = 11;

//        int blocks = ((length - (length % 56)) / 56) + 1;
//        int i = 0;
//        unsigned int schedules[blocks][64];
////        memset(&schedules, 0x00, blocks*64);

//        for(int bl = 0; bl < blocks; bl++) {
//            // write bits to multiple of 512 bit value
////            for(i = 0; i < (length - (bl*64)); i++){
////                prehash[bl][i] = *(input + i + (bl * 64));
////            }
////            memcpy(&prehash[bl], input+(bl*64), (length - (bl*64)));

////            // add a bit 1 to the end of the part message, and add length in bits to the end few bytes
////            // 1000,0000 / 80 hex / 128 dec
////            if (bl+1 == blocks) {
////                prehash[bl][((length*8)-(bl*64*8)) / 8] = 0x80;
////                prehash[bl].write32BitAt(60, length*8);
//////                schedules[bl].write32BitAt(60, length*8);
////            }


//            // blank all fields
//            for(i = 0; i < 64; i++) {
//                schedules[bl][i] = 0;
//            }

//            // this loop amount only works with 2 blocks.
//            for(i = 0; i < 16; i++){
//                if ((length > 32 && bl > 0 && i > 3) || (length == 32 && i > 7)) {
//                    continue;
//                }
//    //            schedule[i] += prehash[(i*4)] << 16;
//                unsigned int one = *(input + (i*4) + (bl * 64)) << 24;
//                unsigned int two = *(input + (i*4) + 1 + (bl * 64)) << 16;
//                unsigned int three = *(input + (i*4) + 2 + (bl * 64)) << 8;
//                unsigned int four = *(input + (i*4) + 3 + (bl * 64));
//                schedules[bl][i] = one + two + three + four;
//            }

//            if (bl+1 == blocks && length > 32) {
//                schedules[bl][4] = 0x80000000;
//                schedules[bl][15] = length*8;
//            } else if ((length == 32) && (bl+1 == blocks)) {
//                schedules[bl][8] = 0x80000000;
//                schedules[bl][15] = length*8;
//            }
//        }


//        // Operator	Symbol	Form	Operation
////        left shift	<<  	x << y	all bits in x shifted left y bits
////        right shift	>>  	x >> y	all bits in x shifted right y bits
////        bitwise NOT	~	    ~x	    all bits in x flipped
////        bitwise AND	&	    x & y	each bit in x AND each bit in y
////        bitwise OR	|	    x | y	each bit in x OR each bit in y
////        bitwise XOR	^	    x ^ y	each bit in x XOR each bit in y

////        const auto p1 = std::chrono::system_clock::now();

//        // compression variables
//        unsigned int sha256_h_buffer[8] = {sha256_h[0],sha256_h[1],sha256_h[2],sha256_h[3],sha256_h[4],sha256_h[5],sha256_h[6],sha256_h[7]};

//        for(int bl = 0; bl < blocks; bl++) {
//    //        For i from w[16…63]:
//    //        s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
//    //        s1 = (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
//    //        w[i] = w[i-16] + s0 + w[i-7] + s1 // (last 32 bits, aka w[i] % 2^32)

//            // fill the schedule arrays
//            for(i = 16; i < 64; i++) {
//                // (n >> d)|(n << (int_bits - d))
////                unsigned int s0 = ((schedules[bl][i-15] >> 7)|(schedules[bl][i-15] << 25)) ^ ((schedules[bl][i-15] >> 18)|(schedules[bl][i-15] << 14)) ^ (schedules[bl][i-15] >> 3);
////                unsigned int s1 = ((schedules[bl][i-2] >> 17)|(schedules[bl][i-2] << 15)) ^ ((schedules[bl][i-2] >> 19)|(schedules[bl][i-2] << 13)) ^ (schedules[bl][i-2] >> 10);
////                unsigned int s0 = rightRotate(schedules[bl][i-15], 7, 32) ^ rightRotate(schedules[bl][i-15], 18, 32) ^ (schedules[bl][i-15] >> 3);
////                unsigned int s1 = rightRotate(schedules[bl][i-2], 17, 32) ^ rightRotate(schedules[bl][i-2], 19, 32) ^ (schedules[bl][i-2] >> 10);
////                unsigned int final = schedules[bl][i-16] + s0 + schedules[bl][i-7] + s1;
//                // modulo 2^32
//    //            schedule[i] = (final - ((final >> 32) & 0xff));
////                schedules[bl][i] = (final << 32) >> 32;
////                schedules[bl][i] = final;
//                schedules[bl][i] = schedules[bl][i-16] + schedules[bl][i-7] + SHA256_F4(schedules[bl][i-2]) + SHA256_F3(schedules[bl][i-15]);
//            }


//            unsigned int a,b,c,d,e,f,g,h;
//            a = sha256_h_buffer[0];
//            b = sha256_h_buffer[1];
//            c = sha256_h_buffer[2];
//            d = sha256_h_buffer[3];
//            e = sha256_h_buffer[4];
//            f = sha256_h_buffer[5];
//            g = sha256_h_buffer[6];
//            h = sha256_h_buffer[7];

//            // COMPRESSION
//            for(i = 0; i < 64; i++) {
//                // (n >> d)|(n << (int_bits - d))
//                //
////                unsigned int s0 = rightRotate(a, 2, 32) ^ rightRotate(a, 13, 32) ^ rightRotate(a, 22, 32);
////                unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
////                unsigned long int temp2 = s0 + maj;
////                unsigned int temp2 = (((a >> 2)|(a << (30))) ^ ((a >> 13)|(a << (19))) ^ ((a >> 22)|(a << (10)))) + ((a & b) ^ (a & c) ^ (b & c));

////                t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
////                    + sha256_k[j] + w[j];
////                t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);

//                unsigned int temp2 = SHA256_F1(a) + SHA2_MAJ(a, b, c);

////                unsigned int s1 = rightRotate(e, 6, 32) ^ rightRotate(e, 11, 32) ^ rightRotate(e, 25, 32);
////                unsigned int ch = (e & f) ^ ((~e) & g);

//                // modulo needed for loop back if bytes > 64
////                unsigned long int temp1 = h + s1 + ch + sha256_k[i] + schedules[bl][i];
////                unsigned int temp1 = h + s1 + ch + sha256_k[i] + schedules[bl][i];
////                unsigned int temp1 = h + (((e >> 6)|(e << (26))) ^ ((e >> 11)|(e << (21))) ^ ((e >> 25)|(e << (7)))) + ((e & f) ^ ((~e) & g)) + sha256_k[i] + schedules[bl][i];
//                unsigned int temp1 = h + SHA256_F2(e) + SHA2_CH(e,f,g) + sha256_k[i] + schedules[bl][i];

//                h = g;
//                g = f;
//                f = e;
////                e = ((unsigned long int)(d + temp1) << 32) >> 32;
//                e = d+temp1;
//                d = c;
//                c = b;
//                b = a;
////                a = ((unsigned long int)(temp1 + temp2) << 32) >> 32;
//                a = temp1+temp2;
//            }

////            sha256_h_buffer[0] = ((unsigned long int)(sha256_h_buffer[0] + a) << 32) >> 32;
////            sha256_h_buffer[1] = ((unsigned long int)(sha256_h_buffer[1] + b) << 32) >> 32;
////            sha256_h_buffer[2] = ((unsigned long int)(sha256_h_buffer[2] + c) << 32) >> 32;
////            sha256_h_buffer[3] = ((unsigned long int)(sha256_h_buffer[3] + d) << 32) >> 32;
////            sha256_h_buffer[4] = ((unsigned long int)(sha256_h_buffer[4] + e) << 32) >> 32;
////            sha256_h_buffer[5] = ((unsigned long int)(sha256_h_buffer[5] + f) << 32) >> 32;
////            sha256_h_buffer[6] = ((unsigned long int)(sha256_h_buffer[6] + g) << 32) >> 32;
////            sha256_h_buffer[7] = ((unsigned long int)(sha256_h_buffer[7] + h) << 32) >> 32;
//            sha256_h_buffer[0] += a;
//            sha256_h_buffer[1] += b;
//            sha256_h_buffer[2] += c;
//            sha256_h_buffer[3] += d;
//            sha256_h_buffer[4] += e;
//            sha256_h_buffer[5] += f;
//            sha256_h_buffer[6] += g;
//            sha256_h_buffer[7] += h;
//        }

////        const auto p2 = std::chrono::system_clock::now();
////        int finaltime = (std::chrono::duration_cast<std::chrono::nanoseconds>(p2.time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::nanoseconds>(p1.time_since_epoch()).count());
////        std::cout << "time taken: " << finaltime << std::endl;

//        uint256<256> digest;
//        digest.write32BitAt(0, sha256_h_buffer[0]);
//        digest.write32BitAt(4, sha256_h_buffer[1]);
//        digest.write32BitAt(8, sha256_h_buffer[2]);
//        digest.write32BitAt(12, sha256_h_buffer[3]);
//        digest.write32BitAt(16, sha256_h_buffer[4]);
//        digest.write32BitAt(20, sha256_h_buffer[5]);
//        digest.write32BitAt(24, sha256_h_buffer[6]);
//        digest.write32BitAt(28, sha256_h_buffer[7]);

//        return digest;


//        // from pdf:
////        S0 = (A rightrotate 2) xor (A rightrotate 13) xor (A rightrotate 22)
////        maj = (A and B) xor (A and C) xor (B and C)
////        t2 = S0 + maj
////        S1 = (E rightrotate 6) xor (E rightrotate 11) xor (E rightrotate 25)
////        ch = (E and F) xor ((not E) and G)
////        t1 = H + S1 + ch + Kt + Wt
////        (A, B, C, D, E, F, G, H) = (t1 + t2, A, B, C, D + t1, E, F, G)

//        // compression loop
////        for i from 0 to 63
////        S1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
////        ch = (e and f) xor ((not e) and g)
////        temp1 = h + S1 + ch + k[i] + w[i]
////        S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
////        maj = (a and b) xor (a and c) xor (b and c)
////        temp2 := S0 + maj
////        h = g
////        g = f
////        e = d + temp1
////        d = c
////        c = b
////        b = a
////        a = temp1 + temp2

////        std::cout << prehash.getHex(false) << std::endl;

////        uint256<256> blank;
////        blank.setHex("0000000000000000000000000000000000000000000000000000000000000000");
////        return blank;
//    }
};

#endif // HASH_H
