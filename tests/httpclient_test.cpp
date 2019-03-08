#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>
#include <chrono>
#include <thread>

#include "../network/http_client.hpp"
#include "mock_http_server.hpp"

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace gruut::net;
using namespace std;

const nlohmann::json SAMPLE_JSON_REQ = R"(
  {
	"req" : "Hello"
  })"_json;

const nlohmann::json SAMPLE_JSON_RES = R"(
  {
    "res": "gruut"
  }
  )"_json;

using namespace boost::property_tree;
using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;

BOOST_AUTO_TEST_SUITE(Test_HttpClient)

  thread th2([](){
     HttpServer mock_server;
     mock_server.config.port = 8080;

     mock_server.resource["^/string$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request){

		 response->write(SAMPLE_JSON_RES.dump());
     };
     mock_server.start();
  });

  BOOST_AUTO_TEST_CASE(Post) {
    this_thread::sleep_for(chrono::seconds(2));
    HttpClient http_client("localhost:8080/string");

  	BOOST_CHECK_EQUAL(http_client.post(SAMPLE_JSON_REQ.dump()), 0);
  }

  BOOST_AUTO_TEST_CASE(PostAndGetReply){
  	HttpClient http_client("localhost:8080/string");

	nlohmann::json reply_json;

	BOOST_CHECK_EQUAL(http_client.postAndGetReply(SAMPLE_JSON_REQ.dump(), reply_json), 0);
	BOOST_CHECK_EQUAL(reply_json, SAMPLE_JSON_RES);

  }

BOOST_AUTO_TEST_SUITE_END()