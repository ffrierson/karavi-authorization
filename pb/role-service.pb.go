// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.15.8
// source: pb/role-service.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type RoleCreateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name        string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	StorageType string `protobuf:"bytes,2,opt,name=storageType,proto3" json:"storageType,omitempty"`
	SystemId    string `protobuf:"bytes,3,opt,name=systemId,proto3" json:"systemId,omitempty"`
	Pool        string `protobuf:"bytes,4,opt,name=pool,proto3" json:"pool,omitempty"`
	Quota       string `protobuf:"bytes,5,opt,name=quota,proto3" json:"quota,omitempty"`
}

func (x *RoleCreateRequest) Reset() {
	*x = RoleCreateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleCreateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleCreateRequest) ProtoMessage() {}

func (x *RoleCreateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleCreateRequest.ProtoReflect.Descriptor instead.
func (*RoleCreateRequest) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{0}
}

func (x *RoleCreateRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *RoleCreateRequest) GetStorageType() string {
	if x != nil {
		return x.StorageType
	}
	return ""
}

func (x *RoleCreateRequest) GetSystemId() string {
	if x != nil {
		return x.SystemId
	}
	return ""
}

func (x *RoleCreateRequest) GetPool() string {
	if x != nil {
		return x.Pool
	}
	return ""
}

func (x *RoleCreateRequest) GetQuota() string {
	if x != nil {
		return x.Quota
	}
	return ""
}

type RoleCreateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RoleCreateResponse) Reset() {
	*x = RoleCreateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleCreateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleCreateResponse) ProtoMessage() {}

func (x *RoleCreateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleCreateResponse.ProtoReflect.Descriptor instead.
func (*RoleCreateResponse) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{1}
}

type RoleDeleteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name        string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	StorageType string `protobuf:"bytes,2,opt,name=storageType,proto3" json:"storageType,omitempty"`
	SystemId    string `protobuf:"bytes,3,opt,name=systemId,proto3" json:"systemId,omitempty"`
	Pool        string `protobuf:"bytes,4,opt,name=pool,proto3" json:"pool,omitempty"`
	Quota       string `protobuf:"bytes,5,opt,name=quota,proto3" json:"quota,omitempty"`
}

func (x *RoleDeleteRequest) Reset() {
	*x = RoleDeleteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleDeleteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleDeleteRequest) ProtoMessage() {}

func (x *RoleDeleteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleDeleteRequest.ProtoReflect.Descriptor instead.
func (*RoleDeleteRequest) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{2}
}

func (x *RoleDeleteRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *RoleDeleteRequest) GetStorageType() string {
	if x != nil {
		return x.StorageType
	}
	return ""
}

func (x *RoleDeleteRequest) GetSystemId() string {
	if x != nil {
		return x.SystemId
	}
	return ""
}

func (x *RoleDeleteRequest) GetPool() string {
	if x != nil {
		return x.Pool
	}
	return ""
}

func (x *RoleDeleteRequest) GetQuota() string {
	if x != nil {
		return x.Quota
	}
	return ""
}

type RoleDeleteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RoleDeleteResponse) Reset() {
	*x = RoleDeleteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleDeleteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleDeleteResponse) ProtoMessage() {}

func (x *RoleDeleteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleDeleteResponse.ProtoReflect.Descriptor instead.
func (*RoleDeleteResponse) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{3}
}

type RoleListRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RoleListRequest) Reset() {
	*x = RoleListRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleListRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleListRequest) ProtoMessage() {}

func (x *RoleListRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleListRequest.ProtoReflect.Descriptor instead.
func (*RoleListRequest) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{4}
}

type RoleListResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Roles []byte `protobuf:"bytes,1,opt,name=roles,proto3" json:"roles,omitempty"`
}

func (x *RoleListResponse) Reset() {
	*x = RoleListResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleListResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleListResponse) ProtoMessage() {}

func (x *RoleListResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleListResponse.ProtoReflect.Descriptor instead.
func (*RoleListResponse) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{5}
}

func (x *RoleListResponse) GetRoles() []byte {
	if x != nil {
		return x.Roles
	}
	return nil
}

type RoleGetRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *RoleGetRequest) Reset() {
	*x = RoleGetRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleGetRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleGetRequest) ProtoMessage() {}

func (x *RoleGetRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleGetRequest.ProtoReflect.Descriptor instead.
func (*RoleGetRequest) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{6}
}

func (x *RoleGetRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type RoleGetResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Role []byte `protobuf:"bytes,1,opt,name=role,proto3" json:"role,omitempty"`
}

func (x *RoleGetResponse) Reset() {
	*x = RoleGetResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleGetResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleGetResponse) ProtoMessage() {}

func (x *RoleGetResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleGetResponse.ProtoReflect.Descriptor instead.
func (*RoleGetResponse) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{7}
}

func (x *RoleGetResponse) GetRole() []byte {
	if x != nil {
		return x.Role
	}
	return nil
}

type RoleUpdateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name        string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	StorageType string `protobuf:"bytes,2,opt,name=storageType,proto3" json:"storageType,omitempty"`
	SystemId    string `protobuf:"bytes,3,opt,name=systemId,proto3" json:"systemId,omitempty"`
	Pool        string `protobuf:"bytes,4,opt,name=pool,proto3" json:"pool,omitempty"`
	Quota       string `protobuf:"bytes,5,opt,name=quota,proto3" json:"quota,omitempty"`
}

func (x *RoleUpdateRequest) Reset() {
	*x = RoleUpdateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleUpdateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleUpdateRequest) ProtoMessage() {}

func (x *RoleUpdateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleUpdateRequest.ProtoReflect.Descriptor instead.
func (*RoleUpdateRequest) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{8}
}

func (x *RoleUpdateRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *RoleUpdateRequest) GetStorageType() string {
	if x != nil {
		return x.StorageType
	}
	return ""
}

func (x *RoleUpdateRequest) GetSystemId() string {
	if x != nil {
		return x.SystemId
	}
	return ""
}

func (x *RoleUpdateRequest) GetPool() string {
	if x != nil {
		return x.Pool
	}
	return ""
}

func (x *RoleUpdateRequest) GetQuota() string {
	if x != nil {
		return x.Quota
	}
	return ""
}

type RoleUpdateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RoleUpdateResponse) Reset() {
	*x = RoleUpdateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_role_service_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleUpdateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleUpdateResponse) ProtoMessage() {}

func (x *RoleUpdateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pb_role_service_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleUpdateResponse.ProtoReflect.Descriptor instead.
func (*RoleUpdateResponse) Descriptor() ([]byte, []int) {
	return file_pb_role_service_proto_rawDescGZIP(), []int{9}
}

var File_pb_role_service_proto protoreflect.FileDescriptor

var file_pb_role_service_proto_rawDesc = []byte{
	0x0a, 0x15, 0x70, 0x62, 0x2f, 0x72, 0x6f, 0x6c, 0x65, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x6b, 0x61, 0x72, 0x61, 0x76, 0x69, 0x22,
	0x8f, 0x01, 0x0a, 0x11, 0x52, 0x6f, 0x6c, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x73,
	0x79, 0x73, 0x74, 0x65, 0x6d, 0x49, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73,
	0x79, 0x73, 0x74, 0x65, 0x6d, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x12, 0x14, 0x0a, 0x05, 0x71,
	0x75, 0x6f, 0x74, 0x61, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x71, 0x75, 0x6f, 0x74,
	0x61, 0x22, 0x14, 0x0a, 0x12, 0x52, 0x6f, 0x6c, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x8f, 0x01, 0x0a, 0x11, 0x52, 0x6f, 0x6c, 0x65,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x20, 0x0a, 0x0b, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x49, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x49, 0x64, 0x12,
	0x12, 0x0a, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70,
	0x6f, 0x6f, 0x6c, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x22, 0x14, 0x0a, 0x12, 0x52, 0x6f, 0x6c,
	0x65, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x11, 0x0a, 0x0f, 0x52, 0x6f, 0x6c, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x22, 0x28, 0x0a, 0x10, 0x52, 0x6f, 0x6c, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x22, 0x24, 0x0a, 0x0e,
	0x52, 0x6f, 0x6c, 0x65, 0x47, 0x65, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x22, 0x25, 0x0a, 0x0f, 0x52, 0x6f, 0x6c, 0x65, 0x47, 0x65, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x22, 0x8f, 0x01, 0x0a, 0x11, 0x52, 0x6f,
	0x6c, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x54, 0x79,
	0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67,
	0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x49,
	0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x49,
	0x64, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x22, 0x14, 0x0a, 0x12, 0x52,
	0x6f, 0x6c, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x32, 0xcd, 0x02, 0x0a, 0x0b, 0x52, 0x6f, 0x6c, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x12, 0x41, 0x0a, 0x06, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x12, 0x19, 0x2e, 0x6b, 0x61,
	0x72, 0x61, 0x76, 0x69, 0x2e, 0x52, 0x6f, 0x6c, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1a, 0x2e, 0x6b, 0x61, 0x72, 0x61, 0x76, 0x69, 0x2e,
	0x52, 0x6f, 0x6c, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x00, 0x12, 0x41, 0x0a, 0x06, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x12, 0x19,
	0x2e, 0x6b, 0x61, 0x72, 0x61, 0x76, 0x69, 0x2e, 0x52, 0x6f, 0x6c, 0x65, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1a, 0x2e, 0x6b, 0x61, 0x72, 0x61,
	0x76, 0x69, 0x2e, 0x52, 0x6f, 0x6c, 0x65, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x3b, 0x0a, 0x04, 0x4c, 0x69, 0x73, 0x74, 0x12,
	0x17, 0x2e, 0x6b, 0x61, 0x72, 0x61, 0x76, 0x69, 0x2e, 0x52, 0x6f, 0x6c, 0x65, 0x4c, 0x69, 0x73,
	0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x6b, 0x61, 0x72, 0x61, 0x76,
	0x69, 0x2e, 0x52, 0x6f, 0x6c, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x00, 0x12, 0x38, 0x0a, 0x03, 0x47, 0x65, 0x74, 0x12, 0x16, 0x2e, 0x6b, 0x61,
	0x72, 0x61, 0x76, 0x69, 0x2e, 0x52, 0x6f, 0x6c, 0x65, 0x47, 0x65, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x6b, 0x61, 0x72, 0x61, 0x76, 0x69, 0x2e, 0x52, 0x6f, 0x6c,
	0x65, 0x47, 0x65, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x41,
	0x0a, 0x06, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x12, 0x19, 0x2e, 0x6b, 0x61, 0x72, 0x61, 0x76,
	0x69, 0x2e, 0x52, 0x6f, 0x6c, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x1a, 0x2e, 0x6b, 0x61, 0x72, 0x61, 0x76, 0x69, 0x2e, 0x52, 0x6f, 0x6c,
	0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x00, 0x42, 0x29, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x64, 0x65, 0x6c, 0x6c, 0x2f, 0x6b, 0x61, 0x72, 0x61, 0x76, 0x69, 0x2d, 0x61, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pb_role_service_proto_rawDescOnce sync.Once
	file_pb_role_service_proto_rawDescData = file_pb_role_service_proto_rawDesc
)

func file_pb_role_service_proto_rawDescGZIP() []byte {
	file_pb_role_service_proto_rawDescOnce.Do(func() {
		file_pb_role_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_pb_role_service_proto_rawDescData)
	})
	return file_pb_role_service_proto_rawDescData
}

var file_pb_role_service_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_pb_role_service_proto_goTypes = []interface{}{
	(*RoleCreateRequest)(nil),  // 0: karavi.RoleCreateRequest
	(*RoleCreateResponse)(nil), // 1: karavi.RoleCreateResponse
	(*RoleDeleteRequest)(nil),  // 2: karavi.RoleDeleteRequest
	(*RoleDeleteResponse)(nil), // 3: karavi.RoleDeleteResponse
	(*RoleListRequest)(nil),    // 4: karavi.RoleListRequest
	(*RoleListResponse)(nil),   // 5: karavi.RoleListResponse
	(*RoleGetRequest)(nil),     // 6: karavi.RoleGetRequest
	(*RoleGetResponse)(nil),    // 7: karavi.RoleGetResponse
	(*RoleUpdateRequest)(nil),  // 8: karavi.RoleUpdateRequest
	(*RoleUpdateResponse)(nil), // 9: karavi.RoleUpdateResponse
}
var file_pb_role_service_proto_depIdxs = []int32{
	0, // 0: karavi.RoleService.Create:input_type -> karavi.RoleCreateRequest
	2, // 1: karavi.RoleService.Delete:input_type -> karavi.RoleDeleteRequest
	4, // 2: karavi.RoleService.List:input_type -> karavi.RoleListRequest
	6, // 3: karavi.RoleService.Get:input_type -> karavi.RoleGetRequest
	8, // 4: karavi.RoleService.Update:input_type -> karavi.RoleUpdateRequest
	1, // 5: karavi.RoleService.Create:output_type -> karavi.RoleCreateResponse
	3, // 6: karavi.RoleService.Delete:output_type -> karavi.RoleDeleteResponse
	5, // 7: karavi.RoleService.List:output_type -> karavi.RoleListResponse
	7, // 8: karavi.RoleService.Get:output_type -> karavi.RoleGetResponse
	9, // 9: karavi.RoleService.Update:output_type -> karavi.RoleUpdateResponse
	5, // [5:10] is the sub-list for method output_type
	0, // [0:5] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_pb_role_service_proto_init() }
func file_pb_role_service_proto_init() {
	if File_pb_role_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pb_role_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleCreateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pb_role_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleCreateResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pb_role_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleDeleteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pb_role_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleDeleteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pb_role_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleListRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pb_role_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleListResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pb_role_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleGetRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pb_role_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleGetResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pb_role_service_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleUpdateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pb_role_service_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleUpdateResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pb_role_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_pb_role_service_proto_goTypes,
		DependencyIndexes: file_pb_role_service_proto_depIdxs,
		MessageInfos:      file_pb_role_service_proto_msgTypes,
	}.Build()
	File_pb_role_service_proto = out.File
	file_pb_role_service_proto_rawDesc = nil
	file_pb_role_service_proto_goTypes = nil
	file_pb_role_service_proto_depIdxs = nil
}
