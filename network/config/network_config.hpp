#pragma once

#include <chrono>
#include <cstddef>
#include <string>

namespace gruut {
namespace net {

constexpr unsigned int DEPTH_B = 5;
constexpr unsigned int PARALLELISM_ALPHA = 3;
constexpr unsigned int KEYSIZE_BITS = 160;
constexpr unsigned int REDUNDANT_SAVE_COUNT = 3;
constexpr unsigned int KBUCKET_SIZE = 20;

constexpr unsigned int NODE_FAILED_COMMS_BEFORE_STALE = 2;
constexpr auto NODE_INACTIVE_TIME_BEFORE_QUESTIONABLE = std::chrono::minutes(15);

constexpr auto PERIODIC_REFRESH_TIMER = std::chrono::seconds(6);
constexpr auto BUCKET_INACTIVE_TIME_BEFORE_REFRESH = std::chrono::seconds(1200);
constexpr auto REQUEST_TIMEOUT = std::chrono::seconds(2);

constexpr unsigned int MAX_THREAD_SIZE = 10;

constexpr size_t KEEP_BROADCAST_MSG_TIME = 180;

//TODO : 임시적으로 사용. 변경될 것.
const std::string DEFAULT_PORT_NUM = "43234";
const std::string IP_ADDRESS = "127.0.0.1";

//TODO : MERGER의 ID를 GA로 받아 올 수 있을때 사용치 않을것. (ID : TEST-MERGER-ID-1TEST-MERGER-ID-1 )
const std::string ID_BASE64 = "VEVTVC1NRVJHRVItSUQtMVRFU1QtTUVSR0VSLUlELTE=";
const std::string MY_ID =  "TEST-MERGER-ID-1TEST-MERGER-ID-1";

}  // namespace net
}  // namespace gruut
