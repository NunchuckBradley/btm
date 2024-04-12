#ifndef TX_H
#define TX_H

#include <iostream>

#include <curl/curl.h>
#include <json/json.h>
#include <json/reader.h>
#include <json/writer.h>
#include <json/value.h>

#include "uint_custom.h"
#include "hash.h"

class Tx {
  public:
    static uint256<256> calculateMerkleRoot(Json::Value block);

    static std::string coinbaseHeight(int height);
    static std::string formatCoinbaseValue(int val, int bytes = 8);
    static std::string legacyAddressToHex(std::string addr);

    static std::string createCoinbase(std::string message, std::string address, int value, int height);
    static std::string blockSubmitHex(std::string header, Json::Value block);
};

#endif // TX_H
