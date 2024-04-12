#include "uint_custom.h"
#include "crypto.h"
#include "hash.h"
#include "tx.h"
//#include "bech32.h"
#include <boost/multiprecision/cpp_int.hpp>

// merkle root ripped from https://github.com/chidionyema/merkleroot/blob/master/MerkleTree.cs
uint256<256> Tx::calculateMerkleRoot(Json::Value merkleLeaves) {
    int leafSize = merkleLeaves.size();
    if (leafSize == 0) {
        uint256<256> empty;
        return empty;
    }
    if (leafSize == 1) {
        uint256<256> last;
        last.setHex(merkleLeaves[0].asString());
        return last;
    }
    if (leafSize % 2 > 0) {
        merkleLeaves.append(merkleLeaves[leafSize - 1]);
        leafSize++;
    }

    Json::Value merkleBranches;

    for (int i = 0; i < leafSize; i += 2) {
        uint256<256>* tx1 = new uint256<256>;
        tx1->setHex(merkleLeaves[i].asString());

        uint256<256>* tx2 = new uint256<256>;
        tx2->setHex(merkleLeaves[i+1].asString());

        tx1->reverseOrder();
        tx2->reverseOrder();

        uint256<512>* combine = new uint256<512>;
        combine->combine(*tx1, *tx2);
        combine->reverseOrder();

//        unsigned char combinedAsChar[64];
//        memset(&combinedAsChar, 0x00, 64);
//        memcpy(&combinedAsChar, &combine, 64);

        uint256<256> leafHash = Hashing::calcMerklHash(combine, 64);
//        uint256<256> leafHash = M_sha256::sha256header(combinedAsChar, 64);

        Json::Value leaf(leafHash.getHex());

        merkleBranches.append(leaf);

        delete tx1;
        delete tx2;
        delete combine;
        // needed otherwise you get 'stack smashing'


    }

    return calculateMerkleRoot(merkleBranches);
}

std::string Tx::coinbaseHeight(int height){
    std::string hex = Crypto::decToHex(height);
    if (hex.size() % 2 > 0) {
        hex = "0" + hex;
    }
    std::string little = Crypto::hexStringLittleEndian(hex);
    std::string size = Crypto::decToHex(little.size()/2);
    if (size.size() % 2 > 0) {
        size = "0" + size;
    }
    return size+little;
}

std::string Tx::formatCoinbaseValue(int value, int bytes) {
    std::string val = Crypto::decToHex(value);
    int i = (bytes*2) - val.size();
    while(i > 0) {
        val = "0" + val;
        i--;
    }
    return Crypto::hexStringLittleEndian(val);
}

std::string Tx::legacyAddressToHex(std::string addr) {
    // IMPORTANT!! LEGACY ADDRESS ONLY
    std::string table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    reverse(addr.begin(), addr.end());

    boost::multiprecision::cpp_int hash160, base;
    base = 58;

    int i = 0;
    while (i < addr.size()) {
        hash160 = hash160 + (boost::multiprecision::cpp_int)(boost::multiprecision::pow(base, i) * table.find(addr[i]));
        i++;
    }

    std::stringstream ss;
    ss<< std::hex << hash160;
    std::string hex ( ss.str() );

    return hex.substr(0, 40);
}

std::string Tx::createCoinbase(std::string message, std::string address, int value, int height){
    // See https://en.bitcoin.it/wiki/Transaction
    // specifications : 2

    std::string coinbase_message = coinbaseHeight(height) + message;

    // Create a pubkey script
    // OP_DUP OP_HASH160 <len to push> <pubkey> OP_EQUALVERIFY OP_CHECKSIG
    // 76   a9           14                      88         ac
    std::string pubkey_script = "76a914" + Tx::legacyAddressToHex(address) + "88ac";

    std::string tx = "";

    tx += "01000000"; // version
    tx += "01"; // inputs (coinbase is 1)
    tx += "0000000000000000000000000000000000000000000000000000000000000000"; // previous hash (coinbase address is empty)
    tx += "ffffffff"; // previous seqnum

    tx += Crypto::decToHex(coinbase_message.size() / 2); // message byte length
    tx += coinbase_message; // message

    tx += "ffffffff"; // seqnum
    tx += "01"; // outputs
    // 8 byte value
    tx += Tx::formatCoinbaseValue(value); // coinbase value
    tx += Crypto::decToHex(pubkey_script.size() / 2); // pubkey_script length
    tx += pubkey_script; // pubkey_script

    tx += "00000000"; // lock-time

    return tx;
}

std::string Tx::blockSubmitHex(std::string header, Json::Value block) {
//        Format a solved block into the ASCII hex submit format.
//        Arguments:
//            block (dict): block template with 'nonce' and 'hash' populated
//        Returns:
//            string: block submission as an ASCII hex string
    std::string submission = header;
    unsigned int tx = block.get("transactions", 0).size();
    if (tx < 0xfd) {
        submission += Tx::formatCoinbaseValue(tx, 1);
    } else if (tx <= 0xffff) {
        submission += "fd" + Tx::formatCoinbaseValue(tx, 2);
    } else if (tx <= 0xffffffff) {
        submission += "fe" + Tx::formatCoinbaseValue(tx, 4);
    } else {
        submission += "ff" + Tx::formatCoinbaseValue(tx, 8);
    }
    std::cout << "submissions: " << submission << std::endl;
    for(int i = 0; i < tx; i++) {
        submission += block["transactions"][i]["data"].asString();
    }
    return submission;
}
