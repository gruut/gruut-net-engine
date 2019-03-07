#include "rpc_services.hpp"
#include <exception>
#include <thread>
#include <future>
#include <cstring>

namespace gruut {
namespace net {

void OpenChannel::proceed() {

  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
	m_receive_status = RpcCallStatus::READ;
	m_context.AsyncNotifyWhenDone(this);
	m_service->RequestOpenChannel(&m_context, &m_stream, m_completion_queue,
								  m_completion_queue, this);
  } break;

  case RpcCallStatus::READ: {
	new OpenChannel(m_service, m_completion_queue, m_signer_table);
	m_receive_status = RpcCallStatus::PROCESS;
	m_stream.Read(&m_request, this);
  } break;

  case RpcCallStatus::PROCESS: {
	m_signer_id_b64 = m_request.sender();
	m_receive_status = RpcCallStatus::WAIT;
	m_signer_table->setReplyMsg(m_signer_id_b64,&m_stream, this);

  } break;

  case RpcCallStatus::WAIT: {
	if (m_context.IsCancelled()) {

	  //TODO : Make internal message and then send it to core
	  m_signer_table->eraseRpcInfo(m_signer_id_b64);
	  delete this;
	}
  } break;

  default:
	break;
  }
}

void GeneralService::proceed() {
	switch (m_receive_status) {
	case RpcCallStatus::CREATE: {
	  m_receive_status = RpcCallStatus::PROCESS;
	  m_service->RequestGeneralService(&m_context, &m_request, &m_responder,
	  						m_completion_queue, m_completion_queue, this);
	}break;

	case RpcCallStatus::PROCESS: {
	  new GeneralService(m_service, m_completion_queue, m_routing_table);

	  Status rpc_status;

	  try {
		std::string packed_msg = m_request.message();

		//TODO: MessageHandler handle message

		if(rpc_status.ok()){
		  m_reply.set_status(grpc_general::MsgStatus_Status_SUCCESS); // SUCCESS
		  m_reply.set_message("OK");
		}
		else{
		  m_reply.set_status(grpc_general::MsgStatus_Status_INVALID); // INVALID
		  m_reply.set_message(rpc_status.error_message());
		}
	  }
	  catch(std::exception &e){ // INTERNAL
		m_reply.set_status(grpc_general::MsgStatus_Status_INTERNAL);
		m_reply.set_message("Merger internal error");
	  }
	  m_receive_status = RpcCallStatus::FINISH;
	  m_responder.Finish(m_reply, rpc_status, this);

	}break;

	default: {
	  delete this;
	}break;
	}
}

void FindNode::proceed() {

  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
	m_receive_status = RpcCallStatus::PROCESS;
	m_service->RequestFindNode(&m_context, &m_request, &m_responder,
					   m_completion_queue, m_completion_queue, this);
  }break;

  case RpcCallStatus::PROCESS: {
	new FindNode(m_service, m_completion_queue, m_routing_table);

	std::string target = m_request.target_id();
	uint64_t time_stamp = m_request.time_stamp();

	auto neighbor_list = m_routing_table->findNeighbors(Hash<160>::sha1(target), PARALLELISM_ALPHA);

	for (const auto &n : neighbor_list) {
	  Neighbors_node *node = m_reply.add_neighbors();

	  node->set_address(n.getEndpoint().address);
	  node->set_port(n.getEndpoint().port);
	  node->set_node_id(n.getId());
	}

	//TODO : current time
	m_reply.set_time_stamp(0);

	Status rpc_status = Status::OK;
	m_receive_status = RpcCallStatus::FINISH;
	m_responder.Finish(m_reply, Status::OK, this);

  }break;

  default: {
	delete this;
  }break;
  }
}

void PingPong::proceed() {

  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
	m_receive_status = RpcCallStatus::PROCESS;
	m_service->RequestPingPong(&m_context, &m_request, &m_responder,
							   m_completion_queue, m_completion_queue, this);
  }break;

  case RpcCallStatus::PROCESS: {
	new PingPong(m_service, m_completion_queue, m_routing_table);

	std::string sender_id = m_request.node_id();
	std::string sender_address = m_request.sender_address();
	std::string sender_port = m_request.sender_port();
	uint32_t version = m_request.version();
	uint64_t time_stamp = m_request.time_stamp();
	//TODO : 받은 Ping 에 대해서 routing table 업데이트 필요.

	//TODO : current time
	m_reply.set_time_stamp(0);
	m_reply.set_version(1);
	m_reply.set_node_id(MY_ID);
	Status rpc_status = Status::OK;

	m_receive_status = RpcCallStatus::FINISH;
	m_responder.Finish(m_reply, rpc_status, this);

  }break;

  default: {
	delete this;
  }break;
  }
}

} //namespace net
} //namespace gruut