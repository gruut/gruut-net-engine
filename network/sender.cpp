#include "sender.hpp"
#include "http_client.hpp"

namespace gruut{
namespace net{

std::unique_ptr<KademliaService::Stub> Sender::genKademliaStub(std::string &addr, std::string &port) {

  auto credential = InsecureChannelCredentials();
  auto channel = CreateChannel(addr + ":" + port, credential);
  return KademliaService::NewStub(channel);
}

PongData Sender::pingReq(std::string &receiver_addr, std::string &receiver_port) {

  auto stub = genKademliaStub(receiver_addr, receiver_port);
  ClientContext context;

  Ping ping;
  ping.set_time_stamp(0);
  ping.set_node_id(MY_ID);
  ping.set_sender_address(IP_ADDRESS);
  ping.set_sender_port(DEFAULT_PORT_NUM);

  Pong pong;
  grpc::Status status = stub->PingPong(&context, ping, &pong);

  PongData ret{pong.node_id(),
               pong.version(),
               pong.time_stamp(),
               status};

  return ret;
}

NeighborsData Sender::findNodeReq(std::string &receiver_addr,
                                  std::string &receiver_port,
                                  const Node::IdType &target_id) {

  auto stub = genKademliaStub(receiver_addr, receiver_port);
  ClientContext context;

  Target target;
  target.set_target_id(target_id);
  target.set_sender_id(MY_ID);
  target.set_sender_address(IP_ADDRESS);
  target.set_sender_port(DEFAULT_PORT_NUM);

  Neighbors neighbors;

  grpc::Status status = stub->FindNode(&context, target, &neighbors);
  std::vector<Node> neighbor_list;

  for(int i=0; i < neighbors.neighbors_size(); i++) {
    const auto &node = neighbors.neighbors(i);
    Node some_node(Hash<160>::sha1(node.node_id()), node.node_id(), node.address(), node.port());
    neighbor_list.emplace_back(some_node);
  }

  return NeighborsData{ neighbor_list, neighbors.time_stamp(), status};
}

}
}