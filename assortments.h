#ifndef ASSORTMENTS_H
#define ASSORTMENTS_H

#include <iostream>

#include <json/json.h>
#include <json/reader.h>
#include <json/writer.h>
#include <json/value.h>

class Assortments {
public:
  static Json::Value stringToJson(std::string str) {
    Json::CharReaderBuilder builder;
    Json::CharReader* reader = builder.newCharReader();
    Json::Value json;
    std::string errors;
    bool parsingSuccessful = reader->parse(
        str.c_str(),
        str.c_str() + str.size(),
        &json,
        &errors
    );
    delete reader;
    if (!parsingSuccessful) {
        std::cout << "Failed to parse the JSON, errors:" << std::endl;
        std::cout << errors << std::endl;
        return 0;
    }
    return json;
  }
  static void reverseChar(char* str, int len) {
      for(int i=0; i<len/2; i++)
          std::swap(str[i], str[len-i-1]);
  }
  static std::string jsonToString(Json::Value json) {
      Json::StreamWriterBuilder builder;
      builder["indentation"] = ""; // If you want whitespace-less output
      return Json::writeString(builder, json);
  }
};




#endif // ASSORTMENTS_H
