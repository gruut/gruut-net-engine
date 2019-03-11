#pragma once

#include <unordered_map>
#include <string>
#include "../kademlia/hash.hpp"

namespace gruut{
namespace net{
  struct IpEndpoint {
	std::string address;
	std::string port;

	bool operator==(IpEndpoint const &rhs) const {
	  return (this->address == rhs.address) && (this->port == rhs.port);
	}
  };

  using IdType = std::string; // 32bytes ID
  using HashedIdType = Hash160; // 32bytes ID를 hash160
}
}
