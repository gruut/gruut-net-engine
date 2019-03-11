#pragma once
#include "rpc_server.hpp"
#include "sender.hpp"
#include <set>

namespace gruut {
namespace net {

class NetworkEngine {
public:
  NetworkEngine();
  NetworkEngine(NetworkEngine const &) = delete;
  NetworkEngine &operator=(NetworkEngine &) = delete;
  NetworkEngine(NetworkEngine &&) = default;
  NetworkEngine &operator=(NetworkEngine &&) = default;

  ~NetworkEngine() = default;

  void run();

private:
  std::shared_ptr<SignerConnTable> m_signer_conn_table;
  std::shared_ptr<RoutingTable> m_routing_table;
  std::shared_ptr<std::set<string>> m_broadcast_check_table;

  Sender m_sender;
  RpcServer m_rpc_server;

  void setUp();
  void pingTask(const Node &node);
  void findNeighborsTask(const Node::IdType &id, const Node::IdTypeHash &hashed_id);
  void refreshBuckets();
  void scheduleRefreshBuckets();

};

} //namespace net
} //namespace gruut