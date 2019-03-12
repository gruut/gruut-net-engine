#pragma once
#include "rpc_server.hpp"
#include "rpc_client.hpp"
#include "http_client.hpp"
#include "config/network_config.hpp"
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

  void setUp();
  void bootStrap();
  void run();

private:
  std::shared_ptr<SignerConnTable> m_signer_conn_table;
  std::shared_ptr<RoutingTable> m_routing_table;
  std::shared_ptr<BroadcastMsgTable> m_broadcast_check_table;

  RpcClient m_rpc_client;
  HttpClient m_http_client;
  RpcServer m_rpc_server;

  void pingTask(const Node &node);
  void findNeighborsTask(const IdType &id, const HashedIdType &hashed_id);
  void refreshBuckets();
  void scheduleRefreshBuckets();
  void refreshBroadcastTable();

  void getNodeInfoFromTracker(int max_node = MAX_NODE_INFO_FROM_TRACKER);

};

} //namespace net
} //namespace gruut