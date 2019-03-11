#include "network_engine.hpp"

namespace gruut{
namespace net{

NetworkEngine::NetworkEngine() {
  m_signer_conn_table = std::make_shared<SignerConnTable>();

  //TODO : 자신의 ID를 인증서버로 부터 받아 올 수 있을 떄 수정 될 것.
  Node my_node(Hash<160>::sha1(MY_ID), MY_ID, IP_ADDRESS, DEFAULT_PORT_NUM);
  m_routing_table = std::make_shared<RoutingTable>(my_node, KBUCKET_SIZE);

  m_broadcast_check_table = std::make_shared<std::set<string>>();
}

void NetworkEngine::setUp(){
  m_rpc_server.setUp(m_signer_conn_table, m_routing_table, m_broadcast_check_table);
  m_sender.setUp(m_broadcast_check_table);
}

void NetworkEngine::run() {

  //TODO : periodic task 실행 되어야 함. ( ScheduleRefreshBuckets 등)
  m_rpc_server.run(DEFAULT_PORT_NUM);
}

void NetworkEngine::pingTask(const Node& node) {
  auto endpoint = node.getEndpoint();
  PongData pong = m_sender.pingReq(endpoint.address,endpoint.port);
  if(!pong.status.ok()){
    bool evicted = m_routing_table->peerTimedOut(node);
    if(!evicted)
      pingTask(node);
  }
}

void NetworkEngine::findNeighborsTask(const gruut::net::Node::IdType &id,
									  const gruut::net::Node::IdTypeHash &hashed_id) {

  auto target_list = m_routing_table->findNeighbors(hashed_id, PARALLELISM_ALPHA);

  for(auto &target : target_list){
	auto endpoint = target.getEndpoint();

	NeighborsData recv_data = m_sender.findNodeReq(endpoint.address, endpoint.port, id);
	if(!recv_data.status.ok()){
	  bool evicted = m_routing_table->peerTimedOut(target);
	  if(!evicted)
		findNeighborsTask(id, hashed_id);
	  else
		return;
	}
	else{
	  for(auto node : recv_data.neighbors) {
		m_routing_table->addPeer(std::move(node));
	  }
	}
  }
}

void NetworkEngine::refreshBuckets() {

  for(auto bucket = m_routing_table->begin(); bucket != m_routing_table->end(); bucket++){
	auto since_last_update = bucket->timeSinceLastUpdated();

	if(since_last_update > BUCKET_INACTIVE_TIME_BEFORE_REFRESH){
	  if(!bucket->empty()){
		const auto &node = bucket->selectRandomNode();
		const auto &id = node.getId();
		const auto &hashed_id = node.getIdHash();

		findNeighborsTask(id, hashed_id);
	  }
	}
  }
}

void NetworkEngine::scheduleRefreshBuckets(){
  static auto bucket_index = 0U;
  auto bucket = m_routing_table->cbegin();

  if(bucket_index < m_routing_table->bucketsCount()){
	std::advance(bucket, bucket_index);
	if(!bucket->empty()){
	  const auto &least_recent_node = bucket->leastRecentlySeenNode();
	  pingTask(least_recent_node);
	}
	++bucket_index;
  }
  else{
	bucket_index = 0;
  }

  refreshBuckets();
}


}
}