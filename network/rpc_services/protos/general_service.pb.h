// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: general_service.proto

#ifndef PROTOBUF_INCLUDED_general_5fservice_2eproto
#define PROTOBUF_INCLUDED_general_5fservice_2eproto

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 3006001
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 3006001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/inlined_string_field.h>
#include <google/protobuf/metadata.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/generated_enum_reflection.h>
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#define PROTOBUF_INTERNAL_EXPORT_protobuf_general_5fservice_2eproto 

namespace protobuf_general_5fservice_2eproto {
// Internal implementation detail -- do not use these members.
struct TableStruct {
  static const ::google::protobuf::internal::ParseTableField entries[];
  static const ::google::protobuf::internal::AuxillaryParseTableField aux[];
  static const ::google::protobuf::internal::ParseTable schema[4];
  static const ::google::protobuf::internal::FieldMetadata field_metadata[];
  static const ::google::protobuf::internal::SerializationTable serialization_table[];
  static const ::google::protobuf::uint32 offsets[];
};
void AddDescriptors();
}  // namespace protobuf_general_5fservice_2eproto
namespace grpc_general {
class Identity;
class IdentityDefaultTypeInternal;
extern IdentityDefaultTypeInternal _Identity_default_instance_;
class MsgStatus;
class MsgStatusDefaultTypeInternal;
extern MsgStatusDefaultTypeInternal _MsgStatus_default_instance_;
class ReplyMsg;
class ReplyMsgDefaultTypeInternal;
extern ReplyMsgDefaultTypeInternal _ReplyMsg_default_instance_;
class RequestMsg;
class RequestMsgDefaultTypeInternal;
extern RequestMsgDefaultTypeInternal _RequestMsg_default_instance_;
}  // namespace grpc_general
namespace google {
namespace protobuf {
template<> ::grpc_general::Identity* Arena::CreateMaybeMessage<::grpc_general::Identity>(Arena*);
template<> ::grpc_general::MsgStatus* Arena::CreateMaybeMessage<::grpc_general::MsgStatus>(Arena*);
template<> ::grpc_general::ReplyMsg* Arena::CreateMaybeMessage<::grpc_general::ReplyMsg>(Arena*);
template<> ::grpc_general::RequestMsg* Arena::CreateMaybeMessage<::grpc_general::RequestMsg>(Arena*);
}  // namespace protobuf
}  // namespace google
namespace grpc_general {

enum MsgStatus_Status {
  MsgStatus_Status_SUCCESS = 0,
  MsgStatus_Status_INVALID = 1,
  MsgStatus_Status_INTERNAL = 2,
  MsgStatus_Status_MsgStatus_Status_INT_MIN_SENTINEL_DO_NOT_USE_ = ::google::protobuf::kint32min,
  MsgStatus_Status_MsgStatus_Status_INT_MAX_SENTINEL_DO_NOT_USE_ = ::google::protobuf::kint32max
};
bool MsgStatus_Status_IsValid(int value);
const MsgStatus_Status MsgStatus_Status_Status_MIN = MsgStatus_Status_SUCCESS;
const MsgStatus_Status MsgStatus_Status_Status_MAX = MsgStatus_Status_INTERNAL;
const int MsgStatus_Status_Status_ARRAYSIZE = MsgStatus_Status_Status_MAX + 1;

const ::google::protobuf::EnumDescriptor* MsgStatus_Status_descriptor();
inline const ::std::string& MsgStatus_Status_Name(MsgStatus_Status value) {
  return ::google::protobuf::internal::NameOfEnum(
    MsgStatus_Status_descriptor(), value);
}
inline bool MsgStatus_Status_Parse(
    const ::std::string& name, MsgStatus_Status* value) {
  return ::google::protobuf::internal::ParseNamedEnum<MsgStatus_Status>(
    MsgStatus_Status_descriptor(), name, value);
}
// ===================================================================

class Identity : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:grpc_general.Identity) */ {
 public:
  Identity();
  virtual ~Identity();

  Identity(const Identity& from);

  inline Identity& operator=(const Identity& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  Identity(Identity&& from) noexcept
    : Identity() {
    *this = ::std::move(from);
  }

  inline Identity& operator=(Identity&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const ::google::protobuf::Descriptor* descriptor();
  static const Identity& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const Identity* internal_default_instance() {
    return reinterpret_cast<const Identity*>(
               &_Identity_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  void Swap(Identity* other);
  friend void swap(Identity& a, Identity& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline Identity* New() const final {
    return CreateMaybeMessage<Identity>(NULL);
  }

  Identity* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<Identity>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const Identity& from);
  void MergeFrom(const Identity& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Identity* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // bytes sender = 1;
  void clear_sender();
  static const int kSenderFieldNumber = 1;
  const ::std::string& sender() const;
  void set_sender(const ::std::string& value);
  #if LANG_CXX11
  void set_sender(::std::string&& value);
  #endif
  void set_sender(const char* value);
  void set_sender(const void* value, size_t size);
  ::std::string* mutable_sender();
  ::std::string* release_sender();
  void set_allocated_sender(::std::string* sender);

  // @@protoc_insertion_point(class_scope:grpc_general.Identity)
 private:

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::ArenaStringPtr sender_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::protobuf_general_5fservice_2eproto::TableStruct;
};
// -------------------------------------------------------------------

class ReplyMsg : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:grpc_general.ReplyMsg) */ {
 public:
  ReplyMsg();
  virtual ~ReplyMsg();

  ReplyMsg(const ReplyMsg& from);

  inline ReplyMsg& operator=(const ReplyMsg& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  ReplyMsg(ReplyMsg&& from) noexcept
    : ReplyMsg() {
    *this = ::std::move(from);
  }

  inline ReplyMsg& operator=(ReplyMsg&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const ::google::protobuf::Descriptor* descriptor();
  static const ReplyMsg& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const ReplyMsg* internal_default_instance() {
    return reinterpret_cast<const ReplyMsg*>(
               &_ReplyMsg_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  void Swap(ReplyMsg* other);
  friend void swap(ReplyMsg& a, ReplyMsg& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline ReplyMsg* New() const final {
    return CreateMaybeMessage<ReplyMsg>(NULL);
  }

  ReplyMsg* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<ReplyMsg>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const ReplyMsg& from);
  void MergeFrom(const ReplyMsg& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(ReplyMsg* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // bytes message = 1;
  void clear_message();
  static const int kMessageFieldNumber = 1;
  const ::std::string& message() const;
  void set_message(const ::std::string& value);
  #if LANG_CXX11
  void set_message(::std::string&& value);
  #endif
  void set_message(const char* value);
  void set_message(const void* value, size_t size);
  ::std::string* mutable_message();
  ::std::string* release_message();
  void set_allocated_message(::std::string* message);

  // @@protoc_insertion_point(class_scope:grpc_general.ReplyMsg)
 private:

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::ArenaStringPtr message_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::protobuf_general_5fservice_2eproto::TableStruct;
};
// -------------------------------------------------------------------

class RequestMsg : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:grpc_general.RequestMsg) */ {
 public:
  RequestMsg();
  virtual ~RequestMsg();

  RequestMsg(const RequestMsg& from);

  inline RequestMsg& operator=(const RequestMsg& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  RequestMsg(RequestMsg&& from) noexcept
    : RequestMsg() {
    *this = ::std::move(from);
  }

  inline RequestMsg& operator=(RequestMsg&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const ::google::protobuf::Descriptor* descriptor();
  static const RequestMsg& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const RequestMsg* internal_default_instance() {
    return reinterpret_cast<const RequestMsg*>(
               &_RequestMsg_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    2;

  void Swap(RequestMsg* other);
  friend void swap(RequestMsg& a, RequestMsg& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline RequestMsg* New() const final {
    return CreateMaybeMessage<RequestMsg>(NULL);
  }

  RequestMsg* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<RequestMsg>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const RequestMsg& from);
  void MergeFrom(const RequestMsg& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(RequestMsg* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // string message_id = 2;
  void clear_message_id();
  static const int kMessageIdFieldNumber = 2;
  const ::std::string& message_id() const;
  void set_message_id(const ::std::string& value);
  #if LANG_CXX11
  void set_message_id(::std::string&& value);
  #endif
  void set_message_id(const char* value);
  void set_message_id(const char* value, size_t size);
  ::std::string* mutable_message_id();
  ::std::string* release_message_id();
  void set_allocated_message_id(::std::string* message_id);

  // bytes message = 3;
  void clear_message();
  static const int kMessageFieldNumber = 3;
  const ::std::string& message() const;
  void set_message(const ::std::string& value);
  #if LANG_CXX11
  void set_message(::std::string&& value);
  #endif
  void set_message(const char* value);
  void set_message(const void* value, size_t size);
  ::std::string* mutable_message();
  ::std::string* release_message();
  void set_allocated_message(::std::string* message);

  // bool broadcast = 1;
  void clear_broadcast();
  static const int kBroadcastFieldNumber = 1;
  bool broadcast() const;
  void set_broadcast(bool value);

  // @@protoc_insertion_point(class_scope:grpc_general.RequestMsg)
 private:

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::ArenaStringPtr message_id_;
  ::google::protobuf::internal::ArenaStringPtr message_;
  bool broadcast_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::protobuf_general_5fservice_2eproto::TableStruct;
};
// -------------------------------------------------------------------

class MsgStatus : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:grpc_general.MsgStatus) */ {
 public:
  MsgStatus();
  virtual ~MsgStatus();

  MsgStatus(const MsgStatus& from);

  inline MsgStatus& operator=(const MsgStatus& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  MsgStatus(MsgStatus&& from) noexcept
    : MsgStatus() {
    *this = ::std::move(from);
  }

  inline MsgStatus& operator=(MsgStatus&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const ::google::protobuf::Descriptor* descriptor();
  static const MsgStatus& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const MsgStatus* internal_default_instance() {
    return reinterpret_cast<const MsgStatus*>(
               &_MsgStatus_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    3;

  void Swap(MsgStatus* other);
  friend void swap(MsgStatus& a, MsgStatus& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline MsgStatus* New() const final {
    return CreateMaybeMessage<MsgStatus>(NULL);
  }

  MsgStatus* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<MsgStatus>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const MsgStatus& from);
  void MergeFrom(const MsgStatus& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(MsgStatus* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  typedef MsgStatus_Status Status;
  static const Status SUCCESS =
    MsgStatus_Status_SUCCESS;
  static const Status INVALID =
    MsgStatus_Status_INVALID;
  static const Status INTERNAL =
    MsgStatus_Status_INTERNAL;
  static inline bool Status_IsValid(int value) {
    return MsgStatus_Status_IsValid(value);
  }
  static const Status Status_MIN =
    MsgStatus_Status_Status_MIN;
  static const Status Status_MAX =
    MsgStatus_Status_Status_MAX;
  static const int Status_ARRAYSIZE =
    MsgStatus_Status_Status_ARRAYSIZE;
  static inline const ::google::protobuf::EnumDescriptor*
  Status_descriptor() {
    return MsgStatus_Status_descriptor();
  }
  static inline const ::std::string& Status_Name(Status value) {
    return MsgStatus_Status_Name(value);
  }
  static inline bool Status_Parse(const ::std::string& name,
      Status* value) {
    return MsgStatus_Status_Parse(name, value);
  }

  // accessors -------------------------------------------------------

  // string message = 2;
  void clear_message();
  static const int kMessageFieldNumber = 2;
  const ::std::string& message() const;
  void set_message(const ::std::string& value);
  #if LANG_CXX11
  void set_message(::std::string&& value);
  #endif
  void set_message(const char* value);
  void set_message(const char* value, size_t size);
  ::std::string* mutable_message();
  ::std::string* release_message();
  void set_allocated_message(::std::string* message);

  // .grpc_general.MsgStatus.Status status = 1;
  void clear_status();
  static const int kStatusFieldNumber = 1;
  ::grpc_general::MsgStatus_Status status() const;
  void set_status(::grpc_general::MsgStatus_Status value);

  // @@protoc_insertion_point(class_scope:grpc_general.MsgStatus)
 private:

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::ArenaStringPtr message_;
  int status_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::protobuf_general_5fservice_2eproto::TableStruct;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// Identity

// bytes sender = 1;
inline void Identity::clear_sender() {
  sender_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& Identity::sender() const {
  // @@protoc_insertion_point(field_get:grpc_general.Identity.sender)
  return sender_.GetNoArena();
}
inline void Identity::set_sender(const ::std::string& value) {
  
  sender_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:grpc_general.Identity.sender)
}
#if LANG_CXX11
inline void Identity::set_sender(::std::string&& value) {
  
  sender_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:grpc_general.Identity.sender)
}
#endif
inline void Identity::set_sender(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  sender_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:grpc_general.Identity.sender)
}
inline void Identity::set_sender(const void* value, size_t size) {
  
  sender_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:grpc_general.Identity.sender)
}
inline ::std::string* Identity::mutable_sender() {
  
  // @@protoc_insertion_point(field_mutable:grpc_general.Identity.sender)
  return sender_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* Identity::release_sender() {
  // @@protoc_insertion_point(field_release:grpc_general.Identity.sender)
  
  return sender_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void Identity::set_allocated_sender(::std::string* sender) {
  if (sender != NULL) {
    
  } else {
    
  }
  sender_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), sender);
  // @@protoc_insertion_point(field_set_allocated:grpc_general.Identity.sender)
}

// -------------------------------------------------------------------

// ReplyMsg

// bytes message = 1;
inline void ReplyMsg::clear_message() {
  message_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& ReplyMsg::message() const {
  // @@protoc_insertion_point(field_get:grpc_general.ReplyMsg.message)
  return message_.GetNoArena();
}
inline void ReplyMsg::set_message(const ::std::string& value) {
  
  message_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:grpc_general.ReplyMsg.message)
}
#if LANG_CXX11
inline void ReplyMsg::set_message(::std::string&& value) {
  
  message_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:grpc_general.ReplyMsg.message)
}
#endif
inline void ReplyMsg::set_message(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  message_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:grpc_general.ReplyMsg.message)
}
inline void ReplyMsg::set_message(const void* value, size_t size) {
  
  message_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:grpc_general.ReplyMsg.message)
}
inline ::std::string* ReplyMsg::mutable_message() {
  
  // @@protoc_insertion_point(field_mutable:grpc_general.ReplyMsg.message)
  return message_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* ReplyMsg::release_message() {
  // @@protoc_insertion_point(field_release:grpc_general.ReplyMsg.message)
  
  return message_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void ReplyMsg::set_allocated_message(::std::string* message) {
  if (message != NULL) {
    
  } else {
    
  }
  message_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), message);
  // @@protoc_insertion_point(field_set_allocated:grpc_general.ReplyMsg.message)
}

// -------------------------------------------------------------------

// RequestMsg

// bool broadcast = 1;
inline void RequestMsg::clear_broadcast() {
  broadcast_ = false;
}
inline bool RequestMsg::broadcast() const {
  // @@protoc_insertion_point(field_get:grpc_general.RequestMsg.broadcast)
  return broadcast_;
}
inline void RequestMsg::set_broadcast(bool value) {
  
  broadcast_ = value;
  // @@protoc_insertion_point(field_set:grpc_general.RequestMsg.broadcast)
}

// string message_id = 2;
inline void RequestMsg::clear_message_id() {
  message_id_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& RequestMsg::message_id() const {
  // @@protoc_insertion_point(field_get:grpc_general.RequestMsg.message_id)
  return message_id_.GetNoArena();
}
inline void RequestMsg::set_message_id(const ::std::string& value) {
  
  message_id_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:grpc_general.RequestMsg.message_id)
}
#if LANG_CXX11
inline void RequestMsg::set_message_id(::std::string&& value) {
  
  message_id_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:grpc_general.RequestMsg.message_id)
}
#endif
inline void RequestMsg::set_message_id(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  message_id_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:grpc_general.RequestMsg.message_id)
}
inline void RequestMsg::set_message_id(const char* value, size_t size) {
  
  message_id_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:grpc_general.RequestMsg.message_id)
}
inline ::std::string* RequestMsg::mutable_message_id() {
  
  // @@protoc_insertion_point(field_mutable:grpc_general.RequestMsg.message_id)
  return message_id_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* RequestMsg::release_message_id() {
  // @@protoc_insertion_point(field_release:grpc_general.RequestMsg.message_id)
  
  return message_id_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void RequestMsg::set_allocated_message_id(::std::string* message_id) {
  if (message_id != NULL) {
    
  } else {
    
  }
  message_id_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), message_id);
  // @@protoc_insertion_point(field_set_allocated:grpc_general.RequestMsg.message_id)
}

// bytes message = 3;
inline void RequestMsg::clear_message() {
  message_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& RequestMsg::message() const {
  // @@protoc_insertion_point(field_get:grpc_general.RequestMsg.message)
  return message_.GetNoArena();
}
inline void RequestMsg::set_message(const ::std::string& value) {
  
  message_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:grpc_general.RequestMsg.message)
}
#if LANG_CXX11
inline void RequestMsg::set_message(::std::string&& value) {
  
  message_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:grpc_general.RequestMsg.message)
}
#endif
inline void RequestMsg::set_message(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  message_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:grpc_general.RequestMsg.message)
}
inline void RequestMsg::set_message(const void* value, size_t size) {
  
  message_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:grpc_general.RequestMsg.message)
}
inline ::std::string* RequestMsg::mutable_message() {
  
  // @@protoc_insertion_point(field_mutable:grpc_general.RequestMsg.message)
  return message_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* RequestMsg::release_message() {
  // @@protoc_insertion_point(field_release:grpc_general.RequestMsg.message)
  
  return message_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void RequestMsg::set_allocated_message(::std::string* message) {
  if (message != NULL) {
    
  } else {
    
  }
  message_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), message);
  // @@protoc_insertion_point(field_set_allocated:grpc_general.RequestMsg.message)
}

// -------------------------------------------------------------------

// MsgStatus

// .grpc_general.MsgStatus.Status status = 1;
inline void MsgStatus::clear_status() {
  status_ = 0;
}
inline ::grpc_general::MsgStatus_Status MsgStatus::status() const {
  // @@protoc_insertion_point(field_get:grpc_general.MsgStatus.status)
  return static_cast< ::grpc_general::MsgStatus_Status >(status_);
}
inline void MsgStatus::set_status(::grpc_general::MsgStatus_Status value) {
  
  status_ = value;
  // @@protoc_insertion_point(field_set:grpc_general.MsgStatus.status)
}

// string message = 2;
inline void MsgStatus::clear_message() {
  message_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& MsgStatus::message() const {
  // @@protoc_insertion_point(field_get:grpc_general.MsgStatus.message)
  return message_.GetNoArena();
}
inline void MsgStatus::set_message(const ::std::string& value) {
  
  message_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:grpc_general.MsgStatus.message)
}
#if LANG_CXX11
inline void MsgStatus::set_message(::std::string&& value) {
  
  message_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:grpc_general.MsgStatus.message)
}
#endif
inline void MsgStatus::set_message(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  message_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:grpc_general.MsgStatus.message)
}
inline void MsgStatus::set_message(const char* value, size_t size) {
  
  message_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:grpc_general.MsgStatus.message)
}
inline ::std::string* MsgStatus::mutable_message() {
  
  // @@protoc_insertion_point(field_mutable:grpc_general.MsgStatus.message)
  return message_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* MsgStatus::release_message() {
  // @@protoc_insertion_point(field_release:grpc_general.MsgStatus.message)
  
  return message_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void MsgStatus::set_allocated_message(::std::string* message) {
  if (message != NULL) {
    
  } else {
    
  }
  message_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), message);
  // @@protoc_insertion_point(field_set_allocated:grpc_general.MsgStatus.message)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------

// -------------------------------------------------------------------

// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace grpc_general

namespace google {
namespace protobuf {

template <> struct is_proto_enum< ::grpc_general::MsgStatus_Status> : ::std::true_type {};
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::grpc_general::MsgStatus_Status>() {
  return ::grpc_general::MsgStatus_Status_descriptor();
}

}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_INCLUDED_general_5fservice_2eproto
