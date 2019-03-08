#include "http_client.hpp"
#include <iostream>
namespace gruut{
namespace net {

CURLcode HttpClient::post(const std::string &packed_msg) {
  try {
	m_curl.setOpt(CURLOPT_URL, m_address.data());
	m_curl.setOpt(CURLOPT_POST, 1L);
	m_curl.setOpt(CURLOPT_TIMEOUT, 2L);

	const auto escaped_field_data = m_curl.escape(packed_msg);
	const std::string post_field = getPostField("message", escaped_field_data);

	m_curl.setOpt(CURLOPT_POSTFIELDS, post_field.data());
	m_curl.setOpt(CURLOPT_POSTFIELDSIZE, post_field.size());

	m_curl.perform();
  } catch (curlpp::EasyException &err) {

	return err.getErrorId();
  }

  return CURLE_OK;
}

CURLcode HttpClient::postAndGetReply(const std::string &msg, nlohmann::json &response_json) {
  try {
	m_curl.setOpt(CURLOPT_URL, m_address.data());
	m_curl.setOpt(CURLOPT_POST, 1L);

	const auto escaped_filed_data = m_curl.escape(msg);
	const std::string post_field = getPostField("message", escaped_filed_data);

	m_curl.setOpt(CURLOPT_POSTFIELDS, post_field.data());
	m_curl.setOpt(CURLOPT_POSTFIELDSIZE, post_field.size());

	std::string http_response;
	m_curl.setOpt(CURLOPT_WRITEFUNCTION, writeCallback);
	m_curl.setOpt(CURLOPT_WRITEDATA, &http_response);
	m_curl.perform();

	response_json = nlohmann::json::parse(http_response);

  } catch (curlpp::EasyException &err) {
	return err.getErrorId();
  } catch (nlohmann::json::parse_error &err) {
	return CURLE_HTTP_POST_ERROR;
  }

  return CURLE_OK;
}

bool HttpClient::checkServStatus() {
  try {
	m_curl.setOpt(CURLOPT_URL, m_address.data());
	m_curl.setOpt(CURLOPT_FAILONERROR, 1L);

	m_curl.perform();
  } catch (curlpp::EasyException &err) {
	return false;
  }
  return true;
}

std::string HttpClient::getPostField(const std::string &key, const std::string &value) {
  const std::string post_field = key + "=" + value;
  return post_field;
}

size_t HttpClient::writeCallback(const char *in, size_t size, size_t num,
								 std::string *out) {
  const size_t total_bytes(size * num);
  out->append(in, total_bytes);
  return total_bytes;
}


}
}