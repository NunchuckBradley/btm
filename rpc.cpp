#include "crypto.h"
#include "rpc.h"

  size_t Rpc::WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
  {
      ((std::string*)userp)->append((char*)contents, size * nmemb);
      return size * nmemb;
  }
  // connect to rpc with this command. send in the desired method and the parameters
  Json::Value Rpc::rpc(std::string method, std::string params) {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if(curl) {
      int id = rand() % 1000;
      std::string ids = std::to_string(id);
      std::string jsonObj = "{\"id\": "+ids+", \"method\": \""+method+"\", \"params\": "+params+"}";

      struct curl_slist *headers = NULL;
      headers = curl_slist_append(headers, "Accept: application/json");
      headers = curl_slist_append(headers, "Content-Type: application/json");
      headers = curl_slist_append(headers, "charset: utf-8");
      std::string auth = "Authorization: Basic "+Crypto::base64_encode("martin:martinpass");
      headers = curl_slist_append(headers, auth.c_str());

      curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8332");
      curl_easy_setopt(curl, CURLOPT_POST, 1);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonObj.c_str());
      // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
      // curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcrp/0.1");

      res = curl_easy_perform(curl);
      curl_easy_cleanup(curl);

      // only use template if id is the same
      Json::Value finale = Assortments::stringToJson(readBuffer);
      if ((finale.get("id", 0).asInt()) == id) {
        return finale.get("result", 0);
      } else {
        std::cout << "Error, id not the same" << std::endl;
      }
    }
    return 0;
  }
  Json::Value Rpc::getblocktemplate() {
    // get a default block template for ease of use
    std::cout << "Getting block template.." << std::endl;
    return rpc("getblocktemplate", "[{\"rules\": [\"segwit\"]}]");
  }

  std::string Rpc::submitblock(std::string* rawblock) {
      CURL *curl;
      CURLcode res;
      std::string readBuffer;

      curl = curl_easy_init();
      if(curl) {
        int id = rand() % 1000;
        std::string ids = std::to_string(id);
        std::string jsonObj = "{\"id\": "+ids+", \"method\": \"submitblock\", \"params\": [\""+*rawblock+"\"]}";

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charset: utf-8");
        std::string auth = "Authorization: Basic "+Crypto::base64_encode("martin:martinpass");
        headers = curl_slist_append(headers, auth.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8332");
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonObj.c_str());
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        // curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcrp/0.1");

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        return readBuffer;
//        // only use template if id is the same
//        Json::Value finale = Assortments::stringToJson(readBuffer);
//        if ((finale.get("id", 0).asInt()) == id) {
//          return finale.get("result", 0);
//        } else {
//          std::cout << "Error, id not the same" << std::endl;
//        }
      }
  }
