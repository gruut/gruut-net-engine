#include "../network/msg_schema.hpp"
#include <boost/test/unit_test.hpp>

using namespace gruut::net;
using namespace std;

BOOST_AUTO_TEST_SUITE(Test_JsonValidator)

  BOOST_AUTO_TEST_CASE(validate_json) {
  	auto MSG_REQ_BLOCK_TRUE_JSON =  R"({
		"mID": "AAAAAAAAAAE=",
		"time": "1543323592",
		"mCert": "-----BEGIN CERTIFICATE-----\nMIIDLDCCAhQCBgEZlK1CPjA....\n-----END CERTIFICATE-----",
		"hgt": "0",
		"mSig": "vQPcP1sloKtQzEP+cOgYwbf0F3QhblPsABOtJrq8nNAEXtibe5J/9B4d4t920JLnQsbZtSMHo...."
	})"_json;

  	auto MSG_REQ_BLOCK_FALSE_JSON = R"({
		"time": "1543323592"
	})"_json;

  	auto MSG_JOIN_TRUE_JSON = R"({
  		"sID": "UAABACACAAE=",
		"time": "1543323592",
		"ver": "1020181127",
		"cID": "AAAAAAAAAAE="
  	})"_json;

	auto MSG_JOIN_FALSE_JSON = R"({
		  "mID": "UAABACACAAE="
	  })"_json;


  	BOOST_TEST(JsonValidator::validateSchema(MSG_REQ_BLOCK_TRUE_JSON, MessageType::MSG_REQ_BLOCK));
  	BOOST_TEST(!JsonValidator::validateSchema(MSG_REQ_BLOCK_FALSE_JSON, MessageType::MSG_REQ_BLOCK));
  	BOOST_TEST(JsonValidator::validateSchema(MSG_JOIN_TRUE_JSON,MessageType ::MSG_JOIN));
  	BOOST_TEST(!JsonValidator::validateSchema(MSG_JOIN_FALSE_JSON,MessageType ::MSG_JOIN));
  }

BOOST_AUTO_TEST_SUITE_END()