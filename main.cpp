#include <cstdlib>
#include <openssl/sha.h>

#include <iostream>
#include <fstream>

#include <chrono>

#include "uint_custom.h"
#include "hash.h"
#include "m_sha256.h"

#include "crypto.h"
#include "rpc.h"
#include "tx.h"


int cltesting();
unsigned int gpu_hashing(uint256<256>* target, unsigned char* header, bool verbose);
unsigned int hashtest(uint256<256>* target, unsigned char* header);

const int HEADERSIZE = 80;
typedef struct block_header2 {
    uint256<32>   version;
    // dont let the "char" fool you, this is binary data not the human readable version
    uint256<256>   prev_block;
    uint256<256>  merkle_root;
    uint256<32>    timestamp;
    uint256<32>    bits;
    uint256<32>    nonce;
} block_header2;


class Mining {
public:
    static std::string printHeaderHex(block_header2 blockheader) {
        return blockheader.version.getHex(false)+blockheader.prev_block.getHex(false)+blockheader.merkle_root.getHex(false)+
                blockheader.timestamp.getHex(false)+blockheader.bits.getHex(false)+blockheader.nonce.getHex(false);
    }
  static std::string mineblock(Json::Value block) {
      // get target
    uint256<256> target;
    target.setHex(block["target"].asString());

    // format header
    block_header2 blockheader;
    blockheader.version = block["version"].asUInt();
    blockheader.prev_block.setHex( block["previousblockhash"].asString() );
    // do merkl root in extranonce loop
    blockheader.timestamp = block["curtime"].asUInt();
    blockheader.bits.setHex( block["bits"].asString() );
    // do nonce in nonce loop
    unsigned char *b = (unsigned char *)&blockheader;


    std::string legacyAddr = "1CqZ1UsPoM8vM253UANeQMtJfwvraJTznm";
    std::string message = "4d7920666972737420626c6f636b206d696e6564212120596970656521";
    unsigned int coinbase = block["coinbasevalue"].asUInt();
    unsigned int height = block["height"].asUInt();

    // initiate coinbase transaction
    Json::Value coinbaseTx;
    block["transactions"].insert(0, coinbaseTx);

    const auto p1 = std::chrono::system_clock::now();
    // starting off a bit lower
    unsigned int extranonce = 0x000FFFFF;
    while (extranonce >= 0 ) {
        unsigned int height = block.get("height", 0).asUInt();
        unsigned int newHeight = Rpc::rpc("getblockcount", "[]").asUInt();
        if (height < newHeight+1) {
            return "Block has been mined before you..";
        }

        unsigned int nonce = 0;
        blockheader.nonce = nonce;

        std::string coinbaseData = Tx::createCoinbase(message+Tx::formatCoinbaseValue(extranonce), legacyAddr, coinbase, height);
        const char* cbdata = coinbaseData.c_str();
        block["transactions"][0]["data"] = coinbaseData;
        block["transactions"][0]["hash"] = Hashing::calcHash((unsigned char*)cbdata, coinbaseData.size()/2).getHex();


        const auto mp1 = std::chrono::system_clock::now();
        // re-calculate merkle root
        Json::Value leaves;
        for(int i = 0; i < block.get("transactions", 0).size(); i++) {
            leaves.append(block["transactions"][i]["hash"]);
        }
        blockheader.merkle_root.setHex(Tx::calculateMerkleRoot(leaves).getHex());

        const auto mp2 = std::chrono::system_clock::now();
        int mfinaltime = (std::chrono::duration_cast<std::chrono::seconds>(mp2.time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(mp1.time_since_epoch()).count());
        std::cout << "Merkle root calculation time: " << mfinaltime << std::endl;

//        std::cout << "Starting nonce loop with extranonce: " << extranonce << std::endl;
        // gpuhashing handlesthe nonce part
        unsigned int nonceFound = gpu_hashing(&target, b, false);

        if (nonceFound > 0) {
            blockheader.nonce = nonceFound;
            std::cout << "Congradulations!! block found!!" << std::endl;
            std::string headerHex = Mining::printHeaderHex(blockheader);
            std::string rawblock = Tx::blockSubmitHex(headerHex, block);
            return Rpc::submitblock(&rawblock);
        }
        else {
            std::cout << "Extra nonce failed: " << extranonce << std::endl;
//            std::cout << "redoing hash..." << std::endl;
        }
//        while (nonce <= 0xFFFFFFFF) {
//            blockheader.nonce = nonce;
//            uint256<256> hash = Hashing::calcHash(b, HEADERSIZE);

//            if (hash < target) {
//                std::cout << "CONGRADULATIONS!! HASH FOUND!!" << std::endl;
//                std::string headerHex = Mining::printHeaderHex(blockheader);
//                return Tx::blockSubmitHex(headerHex, block);
////                return headerHex;
//            }
//            nonce++;
//        }
        extranonce--;
    }

    const auto p2 = std::chrono::system_clock::now();
    int finaltime = (std::chrono::duration_cast<std::chrono::seconds>(p2.time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count());
    std::cout << "finaly time: " << finaltime << std::endl;

    return "";
  }
};


int main(void)
{
//    std::string blocktest = "00000000000000000007ab9208ae4a4861d56dfa8267970b1915ede38920b37f";
//    std::string blocktest = "0000000000000000000b0995542f233ad0bee75bae868c14f8dcb86f209b6915";
//    Json::Value blocktemplate = Rpc::rpc("getblock", "[\""+blocktest+"\"]");

    while(true) {
        Json::Value blocktemplate = Rpc::getblocktemplate();
        time_t now = time(0);
        char* dt = ctime(&now);
        std::cout << "Mining block  " << blocktemplate.get("height", 0).asString() << " on " << dt << std::endl;
        std::cout << Mining::mineblock(blocktemplate) << std::endl;
    }

    return 0;
}


// old block header structure
//typedef struct block_header {
//    unsigned int    version;
//    // dont let the "char" fool you, this is binary data not the human readable version
//    unsigned char   prev_block[32];
//    unsigned char   merkle_root[32];
//    unsigned int    timestamp;
//    unsigned int    bits;
//    unsigned int    nonce;
//} block_header;

//class Header {
//public:
//    unsigned int version;
//    // dont let the "char" fool you, this is binary data not the human readable version
//    unsigned char prev_block[32];
//    unsigned char merkle_root[32];
//    std::string previous_block;
//    std::string tx_merkle_root;
//    unsigned int timestamp;
//    unsigned int bits;
//    std::string bitss;
//    unsigned int nonce;
//    unsigned char final[80];
//    std::string header;

//    std::string makeHeader() {
//        std::string ver, time, bit, non;

//        ver = Crypto::decToHex(version);
//        time = Crypto::decToHex(timestamp);
////            bit = Crypto::decToHex(bits);
//        non = Crypto::decToHex(nonce);

//        std::string vor = Crypto::hexStringLittleEndian(&ver);
//        std::string teem = Crypto::hexStringLittleEndian(&time);
//        std::string beet = Crypto::hexStringLittleEndian(&bitss);
//        std::string nun = Crypto::hexStringLittleEndian(&non);

//        std::string pvb = Crypto::hexStringLittleEndian(&previous_block);
//        std::string mkr = Crypto::hexStringLittleEndian(&tx_merkle_root);
//        header = vor+pvb+mkr+teem+beet+nun;
//        // this is correct, it all combines together fine.

//        return header;
//    }

//    std::string updateHeader(int nonce) {
//        return header.replace(152,8,Crypto::decToHex(nonce));
//    }
//};
//    blockheader.version = Crypto::decToHexLittleEndian(1073676288);
//    Crypto::hexStringToCharBinary(blockheader.prev_block, "000000000000000000069237bbafea14ba06f7bdc5e192aa38875ca3fc0d0cd9", 32);
//    Crypto::hexStringToCharBinary(blockheader.merkle_root, "b0a2b9b8a0063e5b6818a8725ac567977805c77b6bba11f03a0c33a0cdd866ad", 32);
//    blockheader.timestamp = Crypto::decToHexLittleEndian(1612900436);
//    blockheader.bits = Crypto::hexStringLittleEndian("170d21b9");
//    blockheader.nonce = Crypto::decToHexLittleEndian(2792790281);

//    Crypto::byte_swap(blockheader.prev_block, 32);
//    Crypto::byte_swap(blockheader.merkle_root, 32);

    // 670273
    // 000000000000000000040c401545cf049e1f3583583b5603c6e32df3adb383ae
//    blockheader.version = Crypto::decToHexLittleEndian(541065216);
//    Crypto::hexStringToCharBinary(blockheader.prev_block, "00000000000000000009bd722db03e352d6944df0e89a6d94c8156cff1a00967", 32);
//    Crypto::hexStringToCharBinary(blockheader.merkle_root, "573c67ece7fd6c017043c8935e3668eb8a079e3d94841efa440701c44b3c1af9", 32);
//    blockheader.timestamp = Crypto::decToHexLittleEndian(1613136787);
//    blockheader.bits = Crypto::hexStringLittleEndian("170d21b9");
//    blockheader.nonce = Crypto::decToHexLittleEndian(3349225758);

//    Crypto::byte_swap(blockheader.prev_block, 32);
//    Crypto::byte_swap(blockheader.merkle_root, 32);

// start: DEPRECATED
// expected hash
// 000000000000000000064ec839564cc03166184f0a404d82cad9c655f714d886
//Mining::Header header;
//    header.version = 1073676288;
//    header.previous_block = "000000000000000000069237bbafea14ba06f7bdc5e192aa38875ca3fc0d0cd9";
//    header.tx_merkle_root = "b0a2b9b8a0063e5b6818a8725ac567977805c77b6bba11f03a0c33a0cdd866ad";
//    header.timestamp = 1612900436;
//    header.bitss = "170d21b9";
//    header.nonce = 2792790281;
//    std::string headerblock = header.makeHeader();
//    std::cout << headerblock << std::endl;
//    std::string headerblock = header.makeHeader();
//    std::string hashstring = Crypto::getHash(headerblock);
// end: DEPRECATED
