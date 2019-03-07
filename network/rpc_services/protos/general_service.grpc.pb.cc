// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: general_service.proto

#include "general_service.pb.h"
#include "general_service.grpc.pb.h"

#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/method_handler_impl.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>
namespace grpc_general {

static const char* GruutGeneralService_method_names[] = {
  "/grpc_general.GruutGeneralService/OpenChannel",
  "/grpc_general.GruutGeneralService/GeneralService",
};

std::unique_ptr< GruutGeneralService::Stub> GruutGeneralService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< GruutGeneralService::Stub> stub(new GruutGeneralService::Stub(channel));
  return stub;
}

GruutGeneralService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_OpenChannel_(GruutGeneralService_method_names[0], ::grpc::internal::RpcMethod::BIDI_STREAMING, channel)
  , rpcmethod_GeneralService_(GruutGeneralService_method_names[1], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::ClientReaderWriter< ::grpc_general::Identity, ::grpc_general::ReplyMsg>* GruutGeneralService::Stub::OpenChannelRaw(::grpc::ClientContext* context) {
  return ::grpc::internal::ClientReaderWriterFactory< ::grpc_general::Identity, ::grpc_general::ReplyMsg>::Create(channel_.get(), rpcmethod_OpenChannel_, context);
}

::grpc::ClientAsyncReaderWriter< ::grpc_general::Identity, ::grpc_general::ReplyMsg>* GruutGeneralService::Stub::AsyncOpenChannelRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc::internal::ClientAsyncReaderWriterFactory< ::grpc_general::Identity, ::grpc_general::ReplyMsg>::Create(channel_.get(), cq, rpcmethod_OpenChannel_, context, true, tag);
}

::grpc::ClientAsyncReaderWriter< ::grpc_general::Identity, ::grpc_general::ReplyMsg>* GruutGeneralService::Stub::PrepareAsyncOpenChannelRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncReaderWriterFactory< ::grpc_general::Identity, ::grpc_general::ReplyMsg>::Create(channel_.get(), cq, rpcmethod_OpenChannel_, context, false, nullptr);
}

::grpc::Status GruutGeneralService::Stub::GeneralService(::grpc::ClientContext* context, const ::grpc_general::RequestMsg& request, ::grpc_general::MsgStatus* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_GeneralService_, context, request, response);
}

::grpc::ClientAsyncResponseReader< ::grpc_general::MsgStatus>* GruutGeneralService::Stub::AsyncGeneralServiceRaw(::grpc::ClientContext* context, const ::grpc_general::RequestMsg& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::grpc_general::MsgStatus>::Create(channel_.get(), cq, rpcmethod_GeneralService_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::grpc_general::MsgStatus>* GruutGeneralService::Stub::PrepareAsyncGeneralServiceRaw(::grpc::ClientContext* context, const ::grpc_general::RequestMsg& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::grpc_general::MsgStatus>::Create(channel_.get(), cq, rpcmethod_GeneralService_, context, request, false);
}

GruutGeneralService::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      GruutGeneralService_method_names[0],
      ::grpc::internal::RpcMethod::BIDI_STREAMING,
      new ::grpc::internal::BidiStreamingHandler< GruutGeneralService::Service, ::grpc_general::Identity, ::grpc_general::ReplyMsg>(
          std::mem_fn(&GruutGeneralService::Service::OpenChannel), this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      GruutGeneralService_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< GruutGeneralService::Service, ::grpc_general::RequestMsg, ::grpc_general::MsgStatus>(
          std::mem_fn(&GruutGeneralService::Service::GeneralService), this)));
}

GruutGeneralService::Service::~Service() {
}

::grpc::Status GruutGeneralService::Service::OpenChannel(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::grpc_general::ReplyMsg, ::grpc_general::Identity>* stream) {
  (void) context;
  (void) stream;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status GruutGeneralService::Service::GeneralService(::grpc::ServerContext* context, const ::grpc_general::RequestMsg* request, ::grpc_general::MsgStatus* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace grpc_general

