#ifndef RPC_H
#define RPC_H

#include <iostream>
#include <string>

#include <curl/curl.h>
#include <json/json.h>
#include <json/reader.h>
#include <json/writer.h>
#include <json/value.h>

#include "assortments.h"

class Rpc {
public:
    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);
    static Json::Value rpc(std::string method, std::string params = "[]");
    static Json::Value getblocktemplate();
    static std::string submitblock(std::string* rawblock);
};

#endif // RPC_H
