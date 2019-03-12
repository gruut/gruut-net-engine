#include "network_engine.hpp"

namespace gruut{
namespace net{

NetworkEngine::NetworkEngine() {
  m_signer_conn_table = std::make_shared<SignerConnTable>();

  //TODO : 자신의 ID를 인증서버로 부터 받아 올 수 있을 떄 수정 될 것.
  Node my_node(Hash<160>::sha1(MY_ID), MY_ID, IP_ADDRESS, DEFAULT_PORT_NUM);
  m_routing_table = std::make_shared<RoutingTable>(my_node, KBUCKET_SIZE);

  m_broadcast_check_table = std::make_shared<BroadcastMsgTable>();
}

void NetworkEngine::setUp(){
  m_rpc_server.setUp(m_signer_conn_table, m_routing_table, m_broadcast_check_table);
  m_rpc_client.setUp(m_broadcast_check_table);
}

void NetworkEngine::bootStrap() {
  getNodeInfoFromTracker();

  //TODO : BootStrap 단계에서 해야할 일 추가적으로 필요.
}

void NetworkEngine::run() {

  //TODO : periodic task 실행 되어야 함. ( ScheduleRefreshBuckets 등)
  m_rpc_server.run(DEFAULT_PORT_NUM);
}

void NetworkEngine::pingTask(const Node& node) {
  auto endpoint = node.getEndpoint();
  PongData pong = m_rpc_client.pingReq(endpoint.address,endpoint.port);
  if(!pong.status.ok()){
    bool evicted = m_routing_table->peerTimedOut(node);
    if(!evicted)
      pingTask(node);
  }
}

void NetworkEngine::findNeighborsTask(const IdType &id,
									  const HashedIdType &hashed_id) {

  auto target_list = m_routing_table->findNeighbors(hashed_id, PARALLELISM_ALPHA);

  for(auto &target : target_list){
	auto endpoint = target.getEndpoint();

	NeighborsData recv_data = m_rpc_client.findNodeReq(endpoint.address, endpoint.port, id);
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

void NetworkEngine::refreshBroadcastTable(){
  //TODO: gruut util의  Time객체 이용할 것.
  uint64_t now = static_cast<uint64_t>(
	  std::chrono::duration_cast<std::chrono::seconds>(
		  std::chrono::system_clock::now().time_since_epoch())
		  .count());

  for(auto it = m_broadcast_check_table->cbegin(); it != m_broadcast_check_table->cend();){
    if(abs((int)(now - it->second )) > KEEP_BROADCAST_MSG_TIME ) {
	  it = m_broadcast_check_table->erase(it);
	} else {
	  ++it;
	}
  }
}

void NetworkEngine::getNodeInfoFromTracker(int max_node_info) {

  //TODO : post 내용 및 post에 대한 답변에 항목들은 변경 될 것.
  nlohmann::json request_json, response_json;

  request_json["id"] = MY_ID;
  request_json["ip"] = IP_ADDRESS;
  request_json["port"] = DEFAULT_PORT_NUM;
  request_json["max_node"] = max_node_info; //Tracker에게 요청 할 최대 node 수

  m_http_client.postAndGetReply(TRACKER_URL, request_json.dump(), response_json);

  if(response_json.find("nodes") != response_json.end()){
   	 for(auto &node_info : response_json["nodes"]){
   	    // TODO : json 객체 에서 항목을 읽어 올 때 문제가 생길 수 있으므로
   	    // 안전한 방법으로 수정 할 것.
		auto id = node_info["id"].get<std::string>();
		auto ip = node_info["ip"].get<std::string>();
		auto port = node_info["port"].get<std::string>();

		Node node(Hash<160>::sha1(id), id, ip, port);
		m_routing_table->addPeer(std::move(node));
   	 }
  }
}

}
}