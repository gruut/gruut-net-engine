#pragma once

#include "../include/curlpp.hpp"
#include "../include/nlohmann/json.hpp"

namespace gruut{
namespace net{

class HttpClient {
public:
  HttpClient() = delete;
  HttpClient(const std::string &ip, const std::string &port){
    m_address = ip + ":" + port;
  };
  explicit HttpClient(const std::string &url_address) : m_address(url_address) {};

  CURLcode post(const std::string &packed_msg);
  CURLcode postAndGetReply(const std::string &msg, nlohmann::json &response_json);
  bool checkServStatus();

private:
  std::string getPostField(const std::string &key, const std::string &value);
  static size_t writeCallback(const char *in, size_t size, size_t num,
							  std::string *out);

  curlpp::Easy m_curl;
  std::string m_address;
};

}
}