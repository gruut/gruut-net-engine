#ifndef SERVER_HTTP_HPP
#define SERVER_HTTP_HPP

#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <vector>
#include <string>
#include <memory>
#include <atomic>

#ifdef USE_STANDALONE_ASIO
#include <asio.hpp>
#include <asio/steady_timer.hpp>
namespace SimpleWeb {
  using error_code = std::error_code;
  using errc = std::errc;
  namespace make_error_code = std;
} // namespace SimpleWeb
#else
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
namespace SimpleWeb {
namespace asio = boost::asio;
using error_code = boost::system::error_code;
namespace errc = boost::system::errc;
namespace make_error_code = boost::system::errc;
} // namespace SimpleWeb
#endif

// Late 2017 TODO: remove the following checks and always use std::regex
#ifdef USE_BOOST_REGEX
#include <boost/regex.hpp>
namespace SimpleWeb {
  namespace regex = boost;
}
#else
#include <regex>
namespace SimpleWeb {
namespace regex = std;
}
#endif

namespace SimpleWeb {

enum class StatusCode {
  unknown = 0,
  information_continue = 100,
  information_switching_protocols,
  information_processing,
  success_ok = 200,
  success_created,
  success_accepted,
  success_non_authoritative_information,
  success_no_content,
  success_reset_content,
  success_partial_content,
  success_multi_status,
  success_already_reported,
  success_im_used = 226,
  redirection_multiple_choices = 300,
  redirection_moved_permanently,
  redirection_found,
  redirection_see_other,
  redirection_not_modified,
  redirection_use_proxy,
  redirection_switch_proxy,
  redirection_temporary_redirect,
  redirection_permanent_redirect,
  client_error_bad_request = 400,
  client_error_unauthorized,
  client_error_payment_required,
  client_error_forbidden,
  client_error_not_found,
  client_error_method_not_allowed,
  client_error_not_acceptable,
  client_error_proxy_authentication_required,
  client_error_request_timeout,
  client_error_conflict,
  client_error_gone,
  client_error_length_required,
  client_error_precondition_failed,
  client_error_payload_too_large,
  client_error_uri_too_long,
  client_error_unsupported_media_type,
  client_error_range_not_satisfiable,
  client_error_expectation_failed,
  client_error_im_a_teapot,
  client_error_misdirection_required = 421,
  client_error_unprocessable_entity,
  client_error_locked,
  client_error_failed_dependency,
  client_error_upgrade_required = 426,
  client_error_precondition_required = 428,
  client_error_too_many_requests,
  client_error_request_header_fields_too_large = 431,
  client_error_unavailable_for_legal_reasons = 451,
  server_error_internal_server_error = 500,
  server_error_not_implemented,
  server_error_bad_gateway,
  server_error_service_unavailable,
  server_error_gateway_timeout,
  server_error_http_version_not_supported,
  server_error_variant_also_negotiates,
  server_error_insufficient_storage,
  server_error_loop_detected,
  server_error_not_extended = 510,
  server_error_network_authentication_required
};

inline const std::map<StatusCode, std::string> &status_code_strings() {
  static const std::map<StatusCode, std::string> status_code_strings = {
	  {StatusCode::unknown, ""},
	  {StatusCode::information_continue, "100 Continue"},
	  {StatusCode::information_switching_protocols, "101 Switching Protocols"},
	  {StatusCode::information_processing, "102 Processing"},
	  {StatusCode::success_ok, "200 OK"},
	  {StatusCode::success_created, "201 Created"},
	  {StatusCode::success_accepted, "202 Accepted"},
	  {StatusCode::success_non_authoritative_information, "203 Non-Authoritative Information"},
	  {StatusCode::success_no_content, "204 No Content"},
	  {StatusCode::success_reset_content, "205 Reset Content"},
	  {StatusCode::success_partial_content, "206 Partial Content"},
	  {StatusCode::success_multi_status, "207 Multi-Status"},
	  {StatusCode::success_already_reported, "208 Already Reported"},
	  {StatusCode::success_im_used, "226 IM Used"},
	  {StatusCode::redirection_multiple_choices, "300 Multiple Choices"},
	  {StatusCode::redirection_moved_permanently, "301 Moved Permanently"},
	  {StatusCode::redirection_found, "302 Found"},
	  {StatusCode::redirection_see_other, "303 See Other"},
	  {StatusCode::redirection_not_modified, "304 Not Modified"},
	  {StatusCode::redirection_use_proxy, "305 Use Proxy"},
	  {StatusCode::redirection_switch_proxy, "306 Switch Proxy"},
	  {StatusCode::redirection_temporary_redirect, "307 Temporary Redirect"},
	  {StatusCode::redirection_permanent_redirect, "308 Permanent Redirect"},
	  {StatusCode::client_error_bad_request, "400 Bad Request"},
	  {StatusCode::client_error_unauthorized, "401 Unauthorized"},
	  {StatusCode::client_error_payment_required, "402 Payment Required"},
	  {StatusCode::client_error_forbidden, "403 Forbidden"},
	  {StatusCode::client_error_not_found, "404 Not Found"},
	  {StatusCode::client_error_method_not_allowed, "405 Method Not Allowed"},
	  {StatusCode::client_error_not_acceptable, "406 Not Acceptable"},
	  {StatusCode::client_error_proxy_authentication_required, "407 Proxy Authentication Required"},
	  {StatusCode::client_error_request_timeout, "408 Request Timeout"},
	  {StatusCode::client_error_conflict, "409 Conflict"},
	  {StatusCode::client_error_gone, "410 Gone"},
	  {StatusCode::client_error_length_required, "411 Length Required"},
	  {StatusCode::client_error_precondition_failed, "412 Precondition Failed"},
	  {StatusCode::client_error_payload_too_large, "413 Payload Too Large"},
	  {StatusCode::client_error_uri_too_long, "414 URI Too Long"},
	  {StatusCode::client_error_unsupported_media_type, "415 Unsupported Media Type"},
	  {StatusCode::client_error_range_not_satisfiable, "416 Range Not Satisfiable"},
	  {StatusCode::client_error_expectation_failed, "417 Expectation Failed"},
	  {StatusCode::client_error_im_a_teapot, "418 I'm a teapot"},
	  {StatusCode::client_error_misdirection_required, "421 Misdirected Request"},
	  {StatusCode::client_error_unprocessable_entity, "422 Unprocessable Entity"},
	  {StatusCode::client_error_locked, "423 Locked"},
	  {StatusCode::client_error_failed_dependency, "424 Failed Dependency"},
	  {StatusCode::client_error_upgrade_required, "426 Upgrade Required"},
	  {StatusCode::client_error_precondition_required, "428 Precondition Required"},
	  {StatusCode::client_error_too_many_requests, "429 Too Many Requests"},
	  {StatusCode::client_error_request_header_fields_too_large, "431 Request Header Fields Too Large"},
	  {StatusCode::client_error_unavailable_for_legal_reasons, "451 Unavailable For Legal Reasons"},
	  {StatusCode::server_error_internal_server_error, "500 Internal Server Error"},
	  {StatusCode::server_error_not_implemented, "501 Not Implemented"},
	  {StatusCode::server_error_bad_gateway, "502 Bad Gateway"},
	  {StatusCode::server_error_service_unavailable, "503 Service Unavailable"},
	  {StatusCode::server_error_gateway_timeout, "504 Gateway Timeout"},
	  {StatusCode::server_error_http_version_not_supported, "505 HTTP Version Not Supported"},
	  {StatusCode::server_error_variant_also_negotiates, "506 Variant Also Negotiates"},
	  {StatusCode::server_error_insufficient_storage, "507 Insufficient Storage"},
	  {StatusCode::server_error_loop_detected, "508 Loop Detected"},
	  {StatusCode::server_error_not_extended, "510 Not Extended"},
	  {StatusCode::server_error_network_authentication_required, "511 Network Authentication Required"}};
  return status_code_strings;
}

inline StatusCode status_code(const std::string &status_code_string) noexcept {
  class StringToStatusCode : public std::unordered_map<std::string, SimpleWeb::StatusCode> {
  public:
	StringToStatusCode() {
	  for(auto &status_code : status_code_strings())
		emplace(status_code.second, status_code.first);
	}
  };
  static StringToStatusCode string_to_status_code;
  auto pos = string_to_status_code.find(status_code_string);
  if(pos == string_to_status_code.end())
	return StatusCode::unknown;
  return pos->second;
}

inline const std::string &status_code(StatusCode status_code_enum) noexcept {
  auto pos = status_code_strings().find(status_code_enum);
  if(pos == status_code_strings().end()) {
	static std::string empty_string;
	return empty_string;
  }
  return pos->second;
}

inline bool case_insensitive_equal(const std::string &str1, const std::string &str2) noexcept {
  return str1.size() == str2.size() &&
	  std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b) {
		return tolower(a) == tolower(b);
	  });
}
class CaseInsensitiveEqual {
public:
  bool operator()(const std::string &str1, const std::string &str2) const noexcept {
	return case_insensitive_equal(str1, str2);
  }
};
// Based on https://stackoverflow.com/questions/2590677/how-do-i-combine-hash-values-in-c0x/2595226#2595226
class CaseInsensitiveHash {
public:
  std::size_t operator()(const std::string &str) const noexcept {
	std::size_t h = 0;
	std::hash<int> hash;
	for(auto c : str)
	  h ^= hash(tolower(c)) + 0x9e3779b9 + (h << 6) + (h >> 2);
	return h;
  }
};

using CaseInsensitiveMultimap = std::unordered_multimap<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEqual>;

/// Percent encoding and decoding
class Percent {
public:
  /// Returns percent-encoded string
  static std::string encode(const std::string &value) noexcept {
	static auto hex_chars = "0123456789ABCDEF";

	std::string result;
	result.reserve(value.size()); // Minimum size of result

	for(auto &chr : value) {
	  if(!((chr >= '0' && chr <= '9') || (chr >= 'A' && chr <= 'Z') || (chr >= 'a' && chr <= 'z') || chr == '-' || chr == '.' || chr == '_' || chr == '~'))
		result += std::string("%") + hex_chars[static_cast<unsigned char>(chr) >> 4] + hex_chars[static_cast<unsigned char>(chr) & 15];
	  else
		result += chr;
	}

	return result;
  }

  /// Returns percent-decoded string
  static std::string decode(const std::string &value) noexcept {
	std::string result;
	result.reserve(value.size() / 3 + (value.size() % 3)); // Minimum size of result

	for(std::size_t i = 0; i < value.size(); ++i) {
	  auto &chr = value[i];
	  if(chr == '%' && i + 2 < value.size()) {
		auto hex = value.substr(i + 1, 2);
		auto decoded_chr = static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
		result += decoded_chr;
		i += 2;
	  }
	  else if(chr == '+')
		result += ' ';
	  else
		result += chr;
	}

	return result;
  }
};

/// Query string creation and parsing
class QueryString {
public:
  /// Returns query string created from given field names and values
  static std::string create(const CaseInsensitiveMultimap &fields) noexcept {
	std::string result;

	bool first = true;
	for(auto &field : fields) {
	  result += (!first ? "&" : "") + field.first + '=' + Percent::encode(field.second);
	  first = false;
	}

	return result;
  }

  /// Returns query keys with percent-decoded values.
  static CaseInsensitiveMultimap parse(const std::string &query_string) noexcept {
	CaseInsensitiveMultimap result;

	if(query_string.empty())
	  return result;

	std::size_t name_pos = 0;
	auto name_end_pos = std::string::npos;
	auto value_pos = std::string::npos;
	for(std::size_t c = 0; c < query_string.size(); ++c) {
	  if(query_string[c] == '&') {
		auto name = query_string.substr(name_pos, (name_end_pos == std::string::npos ? c : name_end_pos) - name_pos);
		if(!name.empty()) {
		  auto value = value_pos == std::string::npos ? std::string() : query_string.substr(value_pos, c - value_pos);
		  result.emplace(std::move(name), Percent::decode(value));
		}
		name_pos = c + 1;
		name_end_pos = std::string::npos;
		value_pos = std::string::npos;
	  }
	  else if(query_string[c] == '=') {
		name_end_pos = c;
		value_pos = c + 1;
	  }
	}
	if(name_pos < query_string.size()) {
	  auto name = query_string.substr(name_pos, name_end_pos - name_pos);
	  if(!name.empty()) {
		auto value = value_pos >= query_string.size() ? std::string() : query_string.substr(value_pos);
		result.emplace(std::move(name), Percent::decode(value));
	  }
	}

	return result;
  }
};

class HttpHeader {
public:
  /// Parse header fields
  static CaseInsensitiveMultimap parse(std::istream &stream) noexcept {
	CaseInsensitiveMultimap result;
	std::string line;
	getline(stream, line);
	std::size_t param_end;
	while((param_end = line.find(':')) != std::string::npos) {
	  std::size_t value_start = param_end + 1;
	  while(value_start + 1 < line.size() && line[value_start] == ' ')
		++value_start;
	  if(value_start < line.size())
		result.emplace(line.substr(0, param_end), line.substr(value_start, line.size() - value_start - 1));

	  getline(stream, line);
	}
	return result;
  }

  class FieldValue {
  public:
	class SemicolonSeparatedAttributes {
	public:
	  /// Parse Set-Cookie or Content-Disposition header field value. Attribute values are percent-decoded.
	  static CaseInsensitiveMultimap parse(const std::string &str) {
		CaseInsensitiveMultimap result;

		std::size_t name_start_pos = std::string::npos;
		std::size_t name_end_pos = std::string::npos;
		std::size_t value_start_pos = std::string::npos;
		for(std::size_t c = 0; c < str.size(); ++c) {
		  if(name_start_pos == std::string::npos) {
			if(str[c] != ' ' && str[c] != ';')
			  name_start_pos = c;
		  }
		  else {
			if(name_end_pos == std::string::npos) {
			  if(str[c] == ';') {
				result.emplace(str.substr(name_start_pos, c - name_start_pos), std::string());
				name_start_pos = std::string::npos;
			  }
			  else if(str[c] == '=')
				name_end_pos = c;
			}
			else {
			  if(value_start_pos == std::string::npos) {
				if(str[c] == '"' && c + 1 < str.size())
				  value_start_pos = c + 1;
				else
				  value_start_pos = c;
			  }
			  else if(str[c] == '"' || str[c] == ';') {
				result.emplace(str.substr(name_start_pos, name_end_pos - name_start_pos), Percent::decode(str.substr(value_start_pos, c - value_start_pos)));
				name_start_pos = std::string::npos;
				name_end_pos = std::string::npos;
				value_start_pos = std::string::npos;
			  }
			}
		  }
		}
		if(name_start_pos != std::string::npos) {
		  if(name_end_pos == std::string::npos)
			result.emplace(str.substr(name_start_pos), std::string());
		  else if(value_start_pos != std::string::npos) {
			if(str.back() == '"')
			  result.emplace(str.substr(name_start_pos, name_end_pos - name_start_pos), Percent::decode(str.substr(value_start_pos, str.size() - 1)));
			else
			  result.emplace(str.substr(name_start_pos, name_end_pos - name_start_pos), Percent::decode(str.substr(value_start_pos)));
		  }
		}

		return result;
	  }
	};
  };
}; // namespace SimpleWeb

class RequestMessage {
public:
  /// Parse request line and header fields
  static bool parse(std::istream &stream, std::string &method, std::string &path, std::string &query_string, std::string &version, CaseInsensitiveMultimap &header) noexcept {
	header.clear();
	std::string line;
	getline(stream, line);
	std::size_t method_end;
	if((method_end = line.find(' ')) != std::string::npos) {
	  method = line.substr(0, method_end);

	  std::size_t query_start = std::string::npos;
	  std::size_t path_and_query_string_end = std::string::npos;
	  for(std::size_t i = method_end + 1; i < line.size(); ++i) {
		if(line[i] == '?' && (i + 1) < line.size())
		  query_start = i + 1;
		else if(line[i] == ' ') {
		  path_and_query_string_end = i;
		  break;
		}
	  }
	  if(path_and_query_string_end != std::string::npos) {
		if(query_start != std::string::npos) {
		  path = line.substr(method_end + 1, query_start - method_end - 2);
		  query_string = line.substr(query_start, path_and_query_string_end - query_start);
		}
		else
		  path = line.substr(method_end + 1, path_and_query_string_end - method_end - 1);

		std::size_t protocol_end;
		if((protocol_end = line.find('/', path_and_query_string_end + 1)) != std::string::npos) {
		  if(line.compare(path_and_query_string_end + 1, protocol_end - path_and_query_string_end - 1, "HTTP") != 0)
			return false;
		  version = line.substr(protocol_end + 1, line.size() - protocol_end - 2);
		}
		else
		  return false;

		header = HttpHeader::parse(stream);
	  }
	  else
		return false;
	}
	else
	  return false;
	return true;
  }
};

class ResponseMessage {
public:
  /// Parse status line and header fields
  static bool parse(std::istream &stream, std::string &version, std::string &status_code, CaseInsensitiveMultimap &header) noexcept {
	header.clear();
	std::string line;
	getline(stream, line);
	std::size_t version_end = line.find(' ');
	if(version_end != std::string::npos) {
	  if(5 < line.size())
		version = line.substr(5, version_end - 5);
	  else
		return false;
	  if((version_end + 1) < line.size())
		status_code = line.substr(version_end + 1, line.size() - (version_end + 1) - 1);
	  else
		return false;

	  header = HttpHeader::parse(stream);
	}
	else
	  return false;
	return true;
  }
};
} // namespace SimpleWeb

#ifdef __SSE2__
#include <emmintrin.h>
namespace SimpleWeb {
inline void spin_loop_pause() noexcept { _mm_pause(); }
} // namespace SimpleWeb
// TODO: need verification that the following checks are correct:
#elif defined(_MSC_VER) && _MSC_VER >= 1800 && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
namespace SimpleWeb {
  inline void spin_loop_pause() noexcept { _mm_pause(); }
} // namespace SimpleWeb
#else
namespace SimpleWeb {
  inline void spin_loop_pause() noexcept {}
} // namespace SimpleWeb
#endif

namespace SimpleWeb {
/// Makes it possible to for instance cancel Asio handlers without stopping asio::io_service
class ScopeRunner {
  /// Scope count that is set to -1 if scopes are to be canceled
  std::atomic<long> count;

public:
  class SharedLock {
	friend class ScopeRunner;
	std::atomic<long> &count;
	SharedLock(std::atomic<long> &count) noexcept : count(count) {}
	SharedLock &operator=(const SharedLock &) = delete;
	SharedLock(const SharedLock &) = delete;

  public:
	~SharedLock() noexcept {
	  count.fetch_sub(1);
	}
  };

  ScopeRunner() noexcept : count(0) {}

  /// Returns nullptr if scope should be exited, or a shared lock otherwise
  std::unique_ptr<SharedLock> continue_lock() noexcept {
	long expected = count;
	while(expected >= 0 && !count.compare_exchange_weak(expected, expected + 1))
	  spin_loop_pause();

	if(expected < 0)
	  return nullptr;
	else
	  return std::unique_ptr<SharedLock>(new SharedLock(count));
  }

  /// Blocks until all shared locks are released, then prevents future shared locks
  void stop() noexcept {
	long expected = 0;
	while(!count.compare_exchange_weak(expected, -1)) {
	  if(expected < 0)
		return;
	  expected = 0;
	  spin_loop_pause();
	}
  }
};



template <class socket_type>
class Server;

template <class socket_type>
class ServerBase {
protected:
  class Session;

public:
  class Response : public std::enable_shared_from_this<Response>, public std::ostream {
	friend class ServerBase<socket_type>;
	friend class Server<socket_type>;

	asio::streambuf streambuf;

	std::shared_ptr<Session> session;
	long timeout_content;

	Response(std::shared_ptr<Session> session, long timeout_content) noexcept : std::ostream(&streambuf), session(std::move(session)), timeout_content(timeout_content) {}

	template <typename size_type>
	void write_header(const CaseInsensitiveMultimap &header, size_type size) {
	  bool content_length_written = false;
	  bool chunked_transfer_encoding = false;
	  for(auto &field : header) {
		if(!content_length_written && case_insensitive_equal(field.first, "content-length"))
		  content_length_written = true;
		else if(!chunked_transfer_encoding && case_insensitive_equal(field.first, "transfer-encoding") && case_insensitive_equal(field.second, "chunked"))
		  chunked_transfer_encoding = true;

		*this << field.first << ": " << field.second << "\r\n";
	  }
	  if(!content_length_written && !chunked_transfer_encoding && !close_connection_after_response)
		*this << "Content-Length: " << size << "\r\n\r\n";
	  else
		*this << "\r\n";
	}

  public:
	std::size_t size() noexcept {
	  return streambuf.size();
	}

	/// Use this function if you need to recursively send parts of a longer message
	void send(const std::function<void(const error_code &)> &callback = nullptr) noexcept {
	  session->connection->set_timeout(timeout_content);
	  auto self = this->shared_from_this(); // Keep Response instance alive through the following async_write
	  asio::async_write(*session->connection->socket, streambuf, [self, callback](const error_code &ec, std::size_t /*bytes_transferred*/) {
		self->session->connection->cancel_timeout();
		auto lock = self->session->connection->handler_runner->continue_lock();
		if(!lock)
		  return;
		if(callback)
		  callback(ec);
	  });
	}

	/// Write directly to stream buffer using std::ostream::write
	void write(const char_type *ptr, std::streamsize n) {
	  std::ostream::write(ptr, n);
	}

	/// Convenience function for writing status line, potential header fields, and empty content
	void write(StatusCode status_code = StatusCode::success_ok, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
	  *this << "HTTP/1.1 " << SimpleWeb::status_code(status_code) << "\r\n";
	  write_header(header, 0);
	}

	/// Convenience function for writing status line, header fields, and content
	void write(StatusCode status_code, const std::string &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
	  *this << "HTTP/1.1 " << SimpleWeb::status_code(status_code) << "\r\n";
	  write_header(header, content.size());
	  if(!content.empty())
		*this << content;
	}

	/// Convenience function for writing status line, header fields, and content
	void write(StatusCode status_code, std::istream &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
	  *this << "HTTP/1.1 " << SimpleWeb::status_code(status_code) << "\r\n";
	  content.seekg(0, std::ios::end);
	  auto size = content.tellg();
	  content.seekg(0, std::ios::beg);
	  write_header(header, size);
	  if(size)
		*this << content.rdbuf();
	}

	/// Convenience function for writing success status line, header fields, and content
	void write(const std::string &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
	  write(StatusCode::success_ok, content, header);
	}

	/// Convenience function for writing success status line, header fields, and content
	void write(std::istream &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
	  write(StatusCode::success_ok, content, header);
	}

	/// Convenience function for writing success status line, and header fields
	void write(const CaseInsensitiveMultimap &header) {
	  write(StatusCode::success_ok, std::string(), header);
	}

	/// If true, force server to close the connection after the response have been sent.
	///
	/// This is useful when implementing a HTTP/1.0-server sending content
	/// without specifying the content length.
	bool close_connection_after_response = false;
  };

  class Content : public std::istream {
	friend class ServerBase<socket_type>;

  public:
	std::size_t size() noexcept {
	  return streambuf.size();
	}
	/// Convenience function to return std::string. The stream buffer is consumed.
	std::string string() noexcept {
	  try {
		std::string str;
		auto size = streambuf.size();
		str.resize(size);
		read(&str[0], static_cast<std::streamsize>(size));
		return str;
	  }
	  catch(...) {
		return std::string();
	  }
	}

  private:
	asio::streambuf &streambuf;
	Content(asio::streambuf &streambuf) noexcept : std::istream(&streambuf), streambuf(streambuf) {}
  };

  class Request {
	friend class ServerBase<socket_type>;
	friend class Server<socket_type>;
	friend class Session;

	asio::streambuf streambuf;

	Request(std::size_t max_request_streambuf_size, std::shared_ptr<asio::ip::tcp::endpoint> remote_endpoint) noexcept
		: streambuf(max_request_streambuf_size), content(streambuf), remote_endpoint(std::move(remote_endpoint)) {}

  public:
	std::string method, path, query_string, http_version;

	Content content;

	CaseInsensitiveMultimap header;

	regex::smatch path_match;

	std::shared_ptr<asio::ip::tcp::endpoint> remote_endpoint;

	/// The time point when the request header was fully read.
	std::chrono::system_clock::time_point header_read_time;

	std::string remote_endpoint_address() noexcept {
	  try {
		return remote_endpoint->address().to_string();
	  }
	  catch(...) {
		return std::string();
	  }
	}

	unsigned short remote_endpoint_port() noexcept {
	  return remote_endpoint->port();
	}

	/// Returns query keys with percent-decoded values.
	CaseInsensitiveMultimap parse_query_string() noexcept {
	  return SimpleWeb::QueryString::parse(query_string);
	}
  };

protected:
  class Connection : public std::enable_shared_from_this<Connection> {
  public:
	template <typename... Args>
	Connection(std::shared_ptr<ScopeRunner> handler_runner, Args &&... args) noexcept : handler_runner(std::move(handler_runner)), socket(new socket_type(std::forward<Args>(args)...)) {}

	std::shared_ptr<ScopeRunner> handler_runner;

	std::unique_ptr<socket_type> socket; // Socket must be unique_ptr since asio::ssl::stream<asio::ip::tcp::socket> is not movable
	std::mutex socket_close_mutex;

	std::unique_ptr<asio::steady_timer> timer;

	std::shared_ptr<asio::ip::tcp::endpoint> remote_endpoint;

	void close() noexcept {
	  error_code ec;
	  std::unique_lock<std::mutex> lock(socket_close_mutex); // The following operations seems to be needed to run sequentially
	  socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
	  socket->lowest_layer().close(ec);
	}

	void set_timeout(long seconds) noexcept {
	  if(seconds == 0) {
		timer = nullptr;
		return;
	  }

	  timer = std::unique_ptr<asio::steady_timer>(new asio::steady_timer(socket->get_io_service()));
	  timer->expires_from_now(std::chrono::seconds(seconds));
	  auto self = this->shared_from_this();
	  timer->async_wait([self](const error_code &ec) {
		if(!ec)
		  self->close();
	  });
	}

	void cancel_timeout() noexcept {
	  if(timer) {
		error_code ec;
		timer->cancel(ec);
	  }
	}
  };

  class Session {
  public:
	Session(std::size_t max_request_streambuf_size, std::shared_ptr<Connection> connection) noexcept : connection(std::move(connection)) {
	  if(!this->connection->remote_endpoint) {
		error_code ec;
		this->connection->remote_endpoint = std::make_shared<asio::ip::tcp::endpoint>(this->connection->socket->lowest_layer().remote_endpoint(ec));
	  }
	  request = std::shared_ptr<Request>(new Request(max_request_streambuf_size, this->connection->remote_endpoint));
	}

	std::shared_ptr<Connection> connection;
	std::shared_ptr<Request> request;
  };

public:
  class Config {
	friend class ServerBase<socket_type>;

	Config(unsigned short port) noexcept : port(port) {}

  public:
	/// Port number to use. Defaults to 80 for HTTP and 443 for HTTPS. Set to 0 get an assigned port.
	unsigned short port;
	/// If io_service is not set, number of threads that the server will use when start() is called.
	/// Defaults to 1 thread.
	std::size_t thread_pool_size = 1;
	/// Timeout on request handling. Defaults to 5 seconds.
	long timeout_request = 5;
	/// Timeout on content handling. Defaults to 300 seconds.
	long timeout_content = 300;
	/// Maximum size of request stream buffer. Defaults to architecture maximum.
	/// Reaching this limit will result in a message_size error code.
	std::size_t max_request_streambuf_size = std::numeric_limits<std::size_t>::max();
	/// IPv4 address in dotted decimal form or IPv6 address in hexadecimal notation.
	/// If empty, the address will be any address.
	std::string address;
	/// Set to false to avoid binding the socket to an address that is already in use. Defaults to true.
	bool reuse_address = true;
  };
  /// Set before calling start().
  Config config;

private:
  class regex_orderable : public regex::regex {
	std::string str;

  public:
	regex_orderable(const char *regex_cstr) : regex::regex(regex_cstr), str(regex_cstr) {}
	regex_orderable(std::string regex_str) : regex::regex(regex_str), str(std::move(regex_str)) {}
	bool operator<(const regex_orderable &rhs) const noexcept {
	  return str < rhs.str;
	}
  };

public:
  /// Warning: do not add or remove resources after start() is called
  std::map<regex_orderable, std::map<std::string, std::function<void(std::shared_ptr<typename ServerBase<socket_type>::Response>, std::shared_ptr<typename ServerBase<socket_type>::Request>)>>> resource;

  std::map<std::string, std::function<void(std::shared_ptr<typename ServerBase<socket_type>::Response>, std::shared_ptr<typename ServerBase<socket_type>::Request>)>> default_resource;

  std::function<void(std::shared_ptr<typename ServerBase<socket_type>::Request>, const error_code &)> on_error;

  std::function<void(std::unique_ptr<socket_type> &, std::shared_ptr<typename ServerBase<socket_type>::Request>)> on_upgrade;

  /// If you have your own asio::io_service, store its pointer here before running start().
  std::shared_ptr<asio::io_service> io_service;

  /// If you know the server port in advance, use start() instead.
  /// Returns assigned port. If io_service is not set, an internal io_service is created instead.
  /// Call before accept_and_run().
  unsigned short bind() {
	asio::ip::tcp::endpoint endpoint;
	if(config.address.size() > 0)
	  endpoint = asio::ip::tcp::endpoint(asio::ip::address::from_string(config.address), config.port);
	else
	  endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v4(), config.port);

	if(!io_service) {
	  io_service = std::make_shared<asio::io_service>();
	  internal_io_service = true;
	}

	if(!acceptor)
	  acceptor = std::unique_ptr<asio::ip::tcp::acceptor>(new asio::ip::tcp::acceptor(*io_service));
	acceptor->open(endpoint.protocol());
	acceptor->set_option(asio::socket_base::reuse_address(config.reuse_address));
	acceptor->bind(endpoint);

	after_bind();

	return acceptor->local_endpoint().port();
  }

  /// If you know the server port in advance, use start() instead.
  /// Accept requests, and if io_service was not set before calling bind(), run the internal io_service instead.
  /// Call after bind().
  void accept_and_run() {
	acceptor->listen();
	accept();

	if(internal_io_service) {
	  if(io_service->stopped())
		io_service->reset();

	  // If thread_pool_size>1, start m_io_service.run() in (thread_pool_size-1) threads for thread-pooling
	  threads.clear();
	  for(std::size_t c = 1; c < config.thread_pool_size; c++) {
		threads.emplace_back([this]() {
		  this->io_service->run();
		});
	  }

	  // Main thread
	  if(config.thread_pool_size > 0)
		io_service->run();

	  // Wait for the rest of the threads, if any, to finish as well
	  for(auto &t : threads)
		t.join();
	}
  }

  /// Start the server by calling bind() and accept_and_run()
  void start() {
	bind();
	accept_and_run();
  }

  /// Stop accepting new requests, and close current connections.
  void stop() noexcept {
	if(acceptor) {
	  error_code ec;
	  acceptor->close(ec);

	  {
		std::unique_lock<std::mutex> lock(*connections_mutex);
		for(auto &connection : *connections)
		  connection->close();
		connections->clear();
	  }

	  if(internal_io_service)
		io_service->stop();
	}
  }

  virtual ~ServerBase() noexcept {
	handler_runner->stop();
	stop();
  }

protected:
  bool internal_io_service = false;

  std::unique_ptr<asio::ip::tcp::acceptor> acceptor;
  std::vector<std::thread> threads;

  std::shared_ptr<std::unordered_set<Connection *>> connections;
  std::shared_ptr<std::mutex> connections_mutex;

  std::shared_ptr<ScopeRunner> handler_runner;

  ServerBase(unsigned short port) noexcept : config(port), connections(new std::unordered_set<Connection *>()), connections_mutex(new std::mutex()), handler_runner(new ScopeRunner()) {}

  virtual void after_bind() {}
  virtual void accept() = 0;

  template <typename... Args>
  std::shared_ptr<Connection> create_connection(Args &&... args) noexcept {
	auto connections = this->connections;
	auto connections_mutex = this->connections_mutex;
	auto connection = std::shared_ptr<Connection>(new Connection(handler_runner, std::forward<Args>(args)...), [connections, connections_mutex](Connection *connection) {
	  {
		std::unique_lock<std::mutex> lock(*connections_mutex);
		auto it = connections->find(connection);
		if(it != connections->end())
		  connections->erase(it);
	  }
	  delete connection;
	});
	{
	  std::unique_lock<std::mutex> lock(*connections_mutex);
	  connections->emplace(connection.get());
	}
	return connection;
  }

  void read(const std::shared_ptr<Session> &session) {
	session->connection->set_timeout(config.timeout_request);
	asio::async_read_until(*session->connection->socket, session->request->streambuf, "\r\n\r\n", [this, session](const error_code &ec, std::size_t bytes_transferred) {
	  session->connection->cancel_timeout();
	  auto lock = session->connection->handler_runner->continue_lock();
	  if(!lock)
		return;
	  session->request->header_read_time = std::chrono::system_clock::now();
	  if((!ec || ec == asio::error::not_found) && session->request->streambuf.size() == session->request->streambuf.max_size()) {
		auto response = std::shared_ptr<Response>(new Response(session, this->config.timeout_content));
		response->write(StatusCode::client_error_payload_too_large);
		response->send();
		if(this->on_error)
		  this->on_error(session->request, make_error_code::make_error_code(errc::message_size));
		return;
	  }
	  if(!ec) {
		// request->streambuf.size() is not necessarily the same as bytes_transferred, from Boost-docs:
		// "After a successful async_read_until operation, the streambuf may contain additional data beyond the delimiter"
		// The chosen solution is to extract lines from the stream directly when parsing the header. What is left of the
		// streambuf (maybe some bytes of the content) is appended to in the async_read-function below (for retrieving content).
		std::size_t num_additional_bytes = session->request->streambuf.size() - bytes_transferred;

		if(!RequestMessage::parse(session->request->content, session->request->method, session->request->path,
								  session->request->query_string, session->request->http_version, session->request->header)) {
		  if(this->on_error)
			this->on_error(session->request, make_error_code::make_error_code(errc::protocol_error));
		  return;
		}

		// If content, read that as well
		auto header_it = session->request->header.find("Content-Length");
		if(header_it != session->request->header.end()) {
		  unsigned long long content_length = 0;
		  try {
			content_length = stoull(header_it->second);
		  }
		  catch(const std::exception &) {
			if(this->on_error)
			  this->on_error(session->request, make_error_code::make_error_code(errc::protocol_error));
			return;
		  }
		  if(content_length > num_additional_bytes) {
			session->connection->set_timeout(config.timeout_content);
			asio::async_read(*session->connection->socket, session->request->streambuf, asio::transfer_exactly(content_length - num_additional_bytes), [this, session](const error_code &ec, std::size_t /*bytes_transferred*/) {
			  session->connection->cancel_timeout();
			  auto lock = session->connection->handler_runner->continue_lock();
			  if(!lock)
				return;
			  if(!ec) {
				if(session->request->streambuf.size() == session->request->streambuf.max_size()) {
				  auto response = std::shared_ptr<Response>(new Response(session, this->config.timeout_content));
				  response->write(StatusCode::client_error_payload_too_large);
				  response->send();
				  if(this->on_error)
					this->on_error(session->request, make_error_code::make_error_code(errc::message_size));
				  return;
				}
				this->find_resource(session);
			  }
			  else if(this->on_error)
				this->on_error(session->request, ec);
			});
		  }
		  else
			this->find_resource(session);
		}
		else if((header_it = session->request->header.find("Transfer-Encoding")) != session->request->header.end() && header_it->second == "chunked") {
		  auto chunks_streambuf = std::make_shared<asio::streambuf>(this->config.max_request_streambuf_size);
		  this->read_chunked_transfer_encoded(session, chunks_streambuf);
		}
		else
		  this->find_resource(session);
	  }
	  else if(this->on_error)
		this->on_error(session->request, ec);
	});
  }

  void read_chunked_transfer_encoded(const std::shared_ptr<Session> &session, const std::shared_ptr<asio::streambuf> &chunks_streambuf) {
	session->connection->set_timeout(config.timeout_content);
	asio::async_read_until(*session->connection->socket, session->request->streambuf, "\r\n", [this, session, chunks_streambuf](const error_code &ec, size_t bytes_transferred) {
	  session->connection->cancel_timeout();
	  auto lock = session->connection->handler_runner->continue_lock();
	  if(!lock)
		return;
	  if((!ec || ec == asio::error::not_found) && session->request->streambuf.size() == session->request->streambuf.max_size()) {
		auto response = std::shared_ptr<Response>(new Response(session, this->config.timeout_content));
		response->write(StatusCode::client_error_payload_too_large);
		response->send();
		if(this->on_error)
		  this->on_error(session->request, make_error_code::make_error_code(errc::message_size));
		return;
	  }
	  if(!ec) {
		std::string line;
		getline(session->request->content, line);
		bytes_transferred -= line.size() + 1;
		line.pop_back();
		unsigned long length = 0;
		try {
		  length = stoul(line, 0, 16);
		}
		catch(...) {
		  if(this->on_error)
			this->on_error(session->request, make_error_code::make_error_code(errc::protocol_error));
		  return;
		}

		auto num_additional_bytes = session->request->streambuf.size() - bytes_transferred;

		if((2 + length) > num_additional_bytes) {
		  session->connection->set_timeout(config.timeout_content);
		  asio::async_read(*session->connection->socket, session->request->streambuf, asio::transfer_exactly(2 + length - num_additional_bytes), [this, session, chunks_streambuf, length](const error_code &ec, size_t /*bytes_transferred*/) {
			session->connection->cancel_timeout();
			auto lock = session->connection->handler_runner->continue_lock();
			if(!lock)
			  return;
			if(!ec) {
			  if(session->request->streambuf.size() == session->request->streambuf.max_size()) {
				auto response = std::shared_ptr<Response>(new Response(session, this->config.timeout_content));
				response->write(StatusCode::client_error_payload_too_large);
				response->send();
				if(this->on_error)
				  this->on_error(session->request, make_error_code::make_error_code(errc::message_size));
				return;
			  }
			  this->read_chunked_transfer_encoded_chunk(session, chunks_streambuf, length);
			}
			else if(this->on_error)
			  this->on_error(session->request, ec);
		  });
		}
		else
		  this->read_chunked_transfer_encoded_chunk(session, chunks_streambuf, length);
	  }
	  else if(this->on_error)
		this->on_error(session->request, ec);
	});
  }

  void read_chunked_transfer_encoded_chunk(const std::shared_ptr<Session> &session, const std::shared_ptr<asio::streambuf> &chunks_streambuf, unsigned long length) {
	std::ostream tmp_stream(chunks_streambuf.get());
	if(length > 0) {
	  std::unique_ptr<char[]> buffer(new char[length]);
	  session->request->content.read(buffer.get(), static_cast<std::streamsize>(length));
	  tmp_stream.write(buffer.get(), static_cast<std::streamsize>(length));
	  if(chunks_streambuf->size() == chunks_streambuf->max_size()) {
		auto response = std::shared_ptr<Response>(new Response(session, this->config.timeout_content));
		response->write(StatusCode::client_error_payload_too_large);
		response->send();
		if(this->on_error)
		  this->on_error(session->request, make_error_code::make_error_code(errc::message_size));
		return;
	  }
	}

	// Remove "\r\n"
	session->request->content.get();
	session->request->content.get();

	if(length > 0)
	  read_chunked_transfer_encoded(session, chunks_streambuf);
	else {
	  if(chunks_streambuf->size() > 0) {
		std::ostream ostream(&session->request->streambuf);
		ostream << chunks_streambuf.get();
	  }
	  this->find_resource(session);
	}
  }

  void find_resource(const std::shared_ptr<Session> &session) {
	// Upgrade connection
	if(on_upgrade) {
	  auto it = session->request->header.find("Upgrade");
	  if(it != session->request->header.end()) {
		// remove connection from connections
		{
		  std::unique_lock<std::mutex> lock(*connections_mutex);
		  auto it = connections->find(session->connection.get());
		  if(it != connections->end())
			connections->erase(it);
		}

		on_upgrade(session->connection->socket, session->request);
		return;
	  }
	}
	// Find path- and method-match, and call write
	for(auto &regex_method : resource) {
	  auto it = regex_method.second.find(session->request->method);
	  if(it != regex_method.second.end()) {
		regex::smatch sm_res;
		if(regex::regex_match(session->request->path, sm_res, regex_method.first)) {
		  session->request->path_match = std::move(sm_res);
		  write(session, it->second);
		  return;
		}
	  }
	}
	auto it = default_resource.find(session->request->method);
	if(it != default_resource.end())
	  write(session, it->second);
  }

  void write(const std::shared_ptr<Session> &session,
			 std::function<void(std::shared_ptr<typename ServerBase<socket_type>::Response>, std::shared_ptr<typename ServerBase<socket_type>::Request>)> &resource_function) {
	session->connection->set_timeout(config.timeout_content);
	auto response = std::shared_ptr<Response>(new Response(session, config.timeout_content), [this](Response *response_ptr) {
	  auto response = std::shared_ptr<Response>(response_ptr);
	  response->send([this, response](const error_code &ec) {
		if(!ec) {
		  if(response->close_connection_after_response)
			return;

		  auto range = response->session->request->header.equal_range("Connection");
		  for(auto it = range.first; it != range.second; it++) {
			if(case_insensitive_equal(it->second, "close"))
			  return;
			else if(case_insensitive_equal(it->second, "keep-alive")) {
			  auto new_session = std::make_shared<Session>(this->config.max_request_streambuf_size, response->session->connection);
			  this->read(new_session);
			  return;
			}
		  }
		  if(response->session->request->http_version >= "1.1") {
			auto new_session = std::make_shared<Session>(this->config.max_request_streambuf_size, response->session->connection);
			this->read(new_session);
			return;
		  }
		}
		else if(this->on_error)
		  this->on_error(response->session->request, ec);
	  });
	});

	try {
	  resource_function(response, session->request);
	}
	catch(const std::exception &) {
	  if(on_error)
		on_error(session->request, make_error_code::make_error_code(errc::operation_canceled));
	  return;
	}
  }
};

template <class socket_type>
class Server : public ServerBase<socket_type> {};

using HTTP = asio::ip::tcp::socket;

template <>
class Server<HTTP> : public ServerBase<HTTP> {
public:
  Server() noexcept : ServerBase<HTTP>::ServerBase(80) {}

protected:
  void accept() override {
	auto connection = create_connection(*io_service);

	acceptor->async_accept(*connection->socket, [this, connection](const error_code &ec) {
	  auto lock = connection->handler_runner->continue_lock();
	  if(!lock)
		return;

	  // Immediately start accepting a new connection (unless io_service has been stopped)
	  if(ec != asio::error::operation_aborted)
		this->accept();

	  auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);

	  if(!ec) {
		asio::ip::tcp::no_delay option(true);
		error_code ec;
		session->connection->socket->set_option(option, ec);

		this->read(session);
	  }
	  else if(this->on_error)
		this->on_error(session->request, ec);
	});
  }
};
} // namespace SimpleWeb

#endif /* SERVER_HTTP_HPP */