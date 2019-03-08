cmake_minimum_required(VERSION 3.13)
set(CMAKE_CXX_STANDARD 17)

find_package(Boost REQUIRED COMPONENTS system thread unit_test_framework random filesystem serialization)
IF (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIR})
ENDIF (Boost_FOUND)

find_package(CURL REQUIRED)
IF (CURL_FOUND)
    include_directories(${CURL_INCLUDE_DIR})
ENDIF (CURL_FOUND)

file(GLOB UNIT_TEST_SOURCE_FILES
        "kademlia_test.cpp"
        "httpclient_test.cpp"
        "msg_schema_validator_test.cpp"
        )


file(GLOB SOURCE_FILES
         "../include/*.cpp"
         "../network/kademlia/*.cpp"
         "../network/*.cpp"
         "../network/rpc_services/*.cpp"
         "../network/rpc_services/protos/*.cc")

file(GLOB HEADER_FILES
        "../network/kademlia/*.hpp"
        "../network/*.hpp"
        "../network/rpc_services/*.hpp"
        "../network/rpc_services/protos/*.h"
        "mock_http_server.hpp")

set(LIB_PREFIX "/usr/local/lib")
set(BOTAN_LIBS "${LIB_PREFIX}/libbotan-2.a")
set(PROTOBUF_LIBS "${LIB_PREFIX}/libprotobuf.a")

if (APPLE)
    set(GRPC_LIBS
            "${LIB_PREFIX}/libgrpc++.dylib"
            "${LIB_PREFIX}/libgrpc.dylib"
            "${LIB_PREFIX}/libgrpc++_cronet.dylib"
            "${LIB_PREFIX}/libgrpc++_error_details.dylib"
            "${LIB_PREFIX}/libgrpc++_reflection.dylib"
            "${LIB_PREFIX}/libgrpc++_unsecure.dylib"
            "${LIB_PREFIX}/libgrpcpp_channelz.dylib")
else ()
    set(GRPC_LIBS
            "${LIB_PREFIX}/libgrpc++.so"
            "${LIB_PREFIX}/libgrpc.so"
            "${LIB_PREFIX}/libgrpc++_cronet.so"
            "${LIB_PREFIX}/libgrpc++_error_details.so"
            "${LIB_PREFIX}/libgrpc++_reflection.so"
            "${LIB_PREFIX}/libgrpc++_unsecure.so"
            "${LIB_PREFIX}/libgrpcpp_channelz.so")
endif ()

add_definitions(-DBOOST_TEST_DYN_LINK)
add_executable(network_test ${UNIT_TEST_SOURCE_FILES} ${SOURCE_FILES} ${HEADER_FILES})
set_target_properties(network_test PROPERTIES LINKER_LANGUAGE CXX)
target_sources(network_test
                PRIVATE
                ${SOURCE_FILES}
                PUBLIC
                ${HEADER_FILES})

target_include_directories(network_test PRIVATE ../include/)

target_link_libraries(network_test
                    PRIVATE
                    ${CURL_LIBRARIES}
                    ${Boost_LIBRARIES}
                    ${BOTAN_LIBS}
                    ${PROTOBUF_LIBS}
                    ${GRPC_LIBS}
                    )


add_test(
        NAME
        network_test
        COMMAND
        network_test
)


