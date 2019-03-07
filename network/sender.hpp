#pragma once

#include "rpc_services/rpc_services.hpp"
#include <vector>

namespace gruut{
namespace net{

class Sender{
public:
  Sender() = default;

  PongData pingReq(const std::string &receiver_addr, const std::string &receiver_port);
  NeighborsData findNodeReq(const std::string &receiver_addr, const std::string &receiver_port, const Node::IdType &target_id);

private:
  std::unique_ptr< KademliaService::Stub> genKademliaStub(const std::string &addr, const std::string &port);

};

}
}