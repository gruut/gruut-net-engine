#define BOOST_TEST_MODULE

#include <boost/test/unit_test.hpp>
#include "../network/rpc_server.hpp"
#include "../network/sender.hpp"

#include <thread>
#include <future>
#include <chrono>
#include <atomic>
#include <memory>
#include <vector>
#include <set>
#include <random>

using namespace gruut::net;
using namespace std;

const std::string TEST_PORT = "3129";
const std::string LOCAL_ADDR = "127.0.0.1";
const std::string CHARACTERS = "1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";

std::vector<string> genTestID(int num_of_id){
	std::vector<string> random_id_list;

	std::random_device rd;
	std::mt19937 prng(rd());
	std::uniform_int_distribution<> dist(0, CHARACTERS.size()-1);

	for(int i=0; i<num_of_id; i++){
	  std::string tmp{""};
	  for(int j=0; j<32; j++){
	    tmp += CHARACTERS[dist(prng)];
	  }
	  random_id_list.emplace_back(tmp);
	}
	return random_id_list;
}

const std::set<string> TEST_ID_SET = {
	"TEST1",
	"TEST2",
	"TEST3"
};


BOOST_AUTO_TEST_SUITE(Test_KademliaService)

	thread t1([](){

	  	std::vector<Node> node_list;
	  	int cnt = 0;
	  	for(auto &test_id : TEST_ID_SET){
	  	  node_list.emplace_back(
	  	  	Node(Hash<160>::sha1(test_id), test_id, LOCAL_ADDR, TEST_PORT+std::to_string(cnt)));
	  	  cnt++;
	  	}

	  	Node my_node(Hash<160>::sha1(MY_ID), MY_ID, LOCAL_ADDR, DEFAULT_PORT_NUM);

	  	std::shared_ptr<RoutingTable> routing_table =
	  		std::make_shared<RoutingTable>(my_node, KBUCKET_SIZE);

	  	for(auto &node : node_list){
	  	  routing_table->addPeer(std::move(node));
	  	}

	  	std::shared_ptr<SignerConnTable> signer_table =
	  		std::make_shared<SignerConnTable>();

	  	std::shared_ptr<BroadcastMsgTable> broadcast_check_table =
	  		std::make_shared<BroadcastMsgTable>();

	  	RpcServer rpc_server;
	  	rpc_server.setUp(signer_table, routing_table, broadcast_check_table);

	  	rpc_server.run(TEST_PORT);
	});

	BOOST_AUTO_TEST_CASE(self_Ping_Pong) {
  		this_thread::sleep_for(chrono::seconds(2));
		Sender ping_sender;
		auto received_data = ping_sender.pingReq(LOCAL_ADDR, TEST_PORT);

		BOOST_CHECK_EQUAL(received_data.node_id, MY_ID);
		BOOST_CHECK_EQUAL(received_data.version, 1);
		BOOST_TEST(received_data.status.ok());
	}

	BOOST_AUTO_TEST_CASE(self_Find_Node) {
	    Sender find_node_sender;
	    auto random_target = genTestID(1);
	    auto received_data = find_node_sender.findNodeReq(LOCAL_ADDR, TEST_PORT, random_target[0]);

	    for(auto &node : received_data.neighbors){
	      BOOST_TEST(TEST_ID_SET.count(node.getId())!=0);
	    }

	    BOOST_CHECK_EQUAL(received_data.neighbors.size(), TEST_ID_SET.size());
	    BOOST_TEST(received_data.status.ok());
	}

BOOST_AUTO_TEST_SUITE_END()