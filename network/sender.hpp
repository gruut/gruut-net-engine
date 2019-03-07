#pragma once

#include "rpc_service/rpc_services.hpp"
#include "p2p/node.hpp"
#include "message.hpp"
#include <vector>

namespace gruut{
namespace net{

class Sender{
public:
  Sender() = default;

  void sendToMerger();
  void sendToSigner();

  void sendHttpReq(std::string &address, );

  PongData pingReq(std::string &receiver_addr, std::string &receiver_port);
  NeighborsData findNodeReq(std::string &receiver_addr, std::string &receiver_port, const Node::IdType &target_id);

private:

  bool checkMergerMsgType(MessageType msg_type);
  bool checkSignerMsgType(MessageType msg_type);

  std::unique_ptr< KademliaService::Stub> genKademliaStub(std::string &addr, std::string &port);

};

}
}