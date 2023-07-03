// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: authd.proto

package authd

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

type ABRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserName *string `protobuf:"bytes,1,opt,name=user_name,json=userName,proto3,oneof" json:"user_name,omitempty"`
}

func (x *ABRequest) Reset() {
	*x = ABRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ABRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ABRequest) ProtoMessage() {}

func (x *ABRequest) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ABRequest.ProtoReflect.Descriptor instead.
func (*ABRequest) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{0}
}

func (x *ABRequest) GetUserName() string {
	if x != nil && x.UserName != nil {
		return *x.UserName
	}
	return ""
}

type ABResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BrokersInfos   []*ABResponse_BrokerInfo `protobuf:"bytes,1,rep,name=brokers_infos,json=brokersInfos,proto3" json:"brokers_infos,omitempty"`
	PreviousBroker *string                  `protobuf:"bytes,2,opt,name=previous_broker,json=previousBroker,proto3,oneof" json:"previous_broker,omitempty"`
}

func (x *ABResponse) Reset() {
	*x = ABResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ABResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ABResponse) ProtoMessage() {}

func (x *ABResponse) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ABResponse.ProtoReflect.Descriptor instead.
func (*ABResponse) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{1}
}

func (x *ABResponse) GetBrokersInfos() []*ABResponse_BrokerInfo {
	if x != nil {
		return x.BrokersInfos
	}
	return nil
}

func (x *ABResponse) GetPreviousBroker() string {
	if x != nil && x.PreviousBroker != nil {
		return *x.PreviousBroker
	}
	return ""
}

type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{2}
}

type StringResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Msg string `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`
}

func (x *StringResponse) Reset() {
	*x = StringResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StringResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StringResponse) ProtoMessage() {}

func (x *StringResponse) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StringResponse.ProtoReflect.Descriptor instead.
func (*StringResponse) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{3}
}

func (x *StringResponse) GetMsg() string {
	if x != nil {
		return x.Msg
	}
	return ""
}

type SBRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BrokerId           string      `protobuf:"bytes,1,opt,name=broker_id,json=brokerId,proto3" json:"broker_id,omitempty"`
	Username           string      `protobuf:"bytes,2,opt,name=username,proto3" json:"username,omitempty"`
	Lang               string      `protobuf:"bytes,3,opt,name=lang,proto3" json:"lang,omitempty"`
	SupportedUiLayouts []*UILayout `protobuf:"bytes,4,rep,name=supported_ui_layouts,json=supportedUiLayouts,proto3" json:"supported_ui_layouts,omitempty"`
}

func (x *SBRequest) Reset() {
	*x = SBRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SBRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SBRequest) ProtoMessage() {}

func (x *SBRequest) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SBRequest.ProtoReflect.Descriptor instead.
func (*SBRequest) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{4}
}

func (x *SBRequest) GetBrokerId() string {
	if x != nil {
		return x.BrokerId
	}
	return ""
}

func (x *SBRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *SBRequest) GetLang() string {
	if x != nil {
		return x.Lang
	}
	return ""
}

func (x *SBRequest) GetSupportedUiLayouts() []*UILayout {
	if x != nil {
		return x.SupportedUiLayouts
	}
	return nil
}

type UILayout struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	// common components.
	Label  *string `protobuf:"bytes,2,opt,name=label,proto3,oneof" json:"label,omitempty"`
	Button *string `protobuf:"bytes,3,opt,name=button,proto3,oneof" json:"button,omitempty"`
	Wait   *string `protobuf:"bytes,4,opt,name=wait,proto3,oneof" json:"wait,omitempty"`
	// form only.
	Entry *string `protobuf:"bytes,5,opt,name=entry,proto3,oneof" json:"entry,omitempty"`
	// qr code only.
	Content *string `protobuf:"bytes,6,opt,name=content,proto3,oneof" json:"content,omitempty"`
}

func (x *UILayout) Reset() {
	*x = UILayout{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UILayout) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UILayout) ProtoMessage() {}

func (x *UILayout) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UILayout.ProtoReflect.Descriptor instead.
func (*UILayout) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{5}
}

func (x *UILayout) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *UILayout) GetLabel() string {
	if x != nil && x.Label != nil {
		return *x.Label
	}
	return ""
}

func (x *UILayout) GetButton() string {
	if x != nil && x.Button != nil {
		return *x.Button
	}
	return ""
}

func (x *UILayout) GetWait() string {
	if x != nil && x.Wait != nil {
		return *x.Wait
	}
	return ""
}

func (x *UILayout) GetEntry() string {
	if x != nil && x.Entry != nil {
		return *x.Entry
	}
	return ""
}

func (x *UILayout) GetContent() string {
	if x != nil && x.Content != nil {
		return *x.Content
	}
	return ""
}

type SBResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SessionId           string                           `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	EncryptionKey       string                           `protobuf:"bytes,2,opt,name=encryption_key,json=encryptionKey,proto3" json:"encryption_key,omitempty"`
	AuthenticationModes []*SBResponse_AuthenticationMode `protobuf:"bytes,3,rep,name=authentication_modes,json=authenticationModes,proto3" json:"authentication_modes,omitempty"`
}

func (x *SBResponse) Reset() {
	*x = SBResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SBResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SBResponse) ProtoMessage() {}

func (x *SBResponse) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SBResponse.ProtoReflect.Descriptor instead.
func (*SBResponse) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{6}
}

func (x *SBResponse) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

func (x *SBResponse) GetEncryptionKey() string {
	if x != nil {
		return x.EncryptionKey
	}
	return ""
}

func (x *SBResponse) GetAuthenticationModes() []*SBResponse_AuthenticationMode {
	if x != nil {
		return x.AuthenticationModes
	}
	return nil
}

type SAMRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SessionId              string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	AuthenticationModeName string `protobuf:"bytes,2,opt,name=authentication_mode_name,json=authenticationModeName,proto3" json:"authentication_mode_name,omitempty"`
}

func (x *SAMRequest) Reset() {
	*x = SAMRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SAMRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SAMRequest) ProtoMessage() {}

func (x *SAMRequest) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SAMRequest.ProtoReflect.Descriptor instead.
func (*SAMRequest) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{7}
}

func (x *SAMRequest) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

func (x *SAMRequest) GetAuthenticationModeName() string {
	if x != nil {
		return x.AuthenticationModeName
	}
	return ""
}

type SAMResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UiLayoutInfo *UILayout `protobuf:"bytes,1,opt,name=ui_layout_info,json=uiLayoutInfo,proto3" json:"ui_layout_info,omitempty"`
}

func (x *SAMResponse) Reset() {
	*x = SAMResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SAMResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SAMResponse) ProtoMessage() {}

func (x *SAMResponse) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SAMResponse.ProtoReflect.Descriptor instead.
func (*SAMResponse) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{8}
}

func (x *SAMResponse) GetUiLayoutInfo() *UILayout {
	if x != nil {
		return x.UiLayoutInfo
	}
	return nil
}

type IARequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SessionId          string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	AuthenticationData string `protobuf:"bytes,2,opt,name=authentication_data,json=authenticationData,proto3" json:"authentication_data,omitempty"`
}

func (x *IARequest) Reset() {
	*x = IARequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IARequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IARequest) ProtoMessage() {}

func (x *IARequest) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IARequest.ProtoReflect.Descriptor instead.
func (*IARequest) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{9}
}

func (x *IARequest) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

func (x *IARequest) GetAuthenticationData() string {
	if x != nil {
		return x.AuthenticationData
	}
	return ""
}

type IAResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Access   string            `protobuf:"bytes,1,opt,name=access,proto3" json:"access,omitempty"`
	UserInfo map[string]string `protobuf:"bytes,2,rep,name=user_info,json=userInfo,proto3" json:"user_info,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *IAResponse) Reset() {
	*x = IAResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IAResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IAResponse) ProtoMessage() {}

func (x *IAResponse) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IAResponse.ProtoReflect.Descriptor instead.
func (*IAResponse) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{10}
}

func (x *IAResponse) GetAccess() string {
	if x != nil {
		return x.Access
	}
	return ""
}

func (x *IAResponse) GetUserInfo() map[string]string {
	if x != nil {
		return x.UserInfo
	}
	return nil
}

type ABResponse_BrokerInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id        string  `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name      string  `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	BrandIcon *string `protobuf:"bytes,3,opt,name=brand_icon,json=brandIcon,proto3,oneof" json:"brand_icon,omitempty"`
}

func (x *ABResponse_BrokerInfo) Reset() {
	*x = ABResponse_BrokerInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ABResponse_BrokerInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ABResponse_BrokerInfo) ProtoMessage() {}

func (x *ABResponse_BrokerInfo) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ABResponse_BrokerInfo.ProtoReflect.Descriptor instead.
func (*ABResponse_BrokerInfo) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{1, 0}
}

func (x *ABResponse_BrokerInfo) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ABResponse_BrokerInfo) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ABResponse_BrokerInfo) GetBrandIcon() string {
	if x != nil && x.BrandIcon != nil {
		return *x.BrandIcon
	}
	return ""
}

type SBResponse_AuthenticationMode struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Label string `protobuf:"bytes,2,opt,name=label,proto3" json:"label,omitempty"`
}

func (x *SBResponse_AuthenticationMode) Reset() {
	*x = SBResponse_AuthenticationMode{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authd_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SBResponse_AuthenticationMode) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SBResponse_AuthenticationMode) ProtoMessage() {}

func (x *SBResponse_AuthenticationMode) ProtoReflect() protoreflect.Message {
	mi := &file_authd_proto_msgTypes[12]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SBResponse_AuthenticationMode.ProtoReflect.Descriptor instead.
func (*SBResponse_AuthenticationMode) Descriptor() ([]byte, []int) {
	return file_authd_proto_rawDescGZIP(), []int{6, 0}
}

func (x *SBResponse_AuthenticationMode) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *SBResponse_AuthenticationMode) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}

var File_authd_proto protoreflect.FileDescriptor

var file_authd_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x61, 0x75, 0x74, 0x68, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x3b, 0x0a,
	0x09, 0x41, 0x42, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x09, 0x75, 0x73,
	0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52,
	0x08, 0x75, 0x73, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x88, 0x01, 0x01, 0x42, 0x0c, 0x0a, 0x0a,
	0x5f, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0xf0, 0x01, 0x0a, 0x0a, 0x41,
	0x42, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3b, 0x0a, 0x0d, 0x62, 0x72, 0x6f,
	0x6b, 0x65, 0x72, 0x73, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x16, 0x2e, 0x41, 0x42, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x42, 0x72,
	0x6f, 0x6b, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0c, 0x62, 0x72, 0x6f, 0x6b, 0x65, 0x72,
	0x73, 0x49, 0x6e, 0x66, 0x6f, 0x73, 0x12, 0x2c, 0x0a, 0x0f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x6f,
	0x75, 0x73, 0x5f, 0x62, 0x72, 0x6f, 0x6b, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x00, 0x52, 0x0e, 0x70, 0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x42, 0x72, 0x6f, 0x6b, 0x65,
	0x72, 0x88, 0x01, 0x01, 0x1a, 0x63, 0x0a, 0x0a, 0x42, 0x72, 0x6f, 0x6b, 0x65, 0x72, 0x49, 0x6e,
	0x66, 0x6f, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02,
	0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x22, 0x0a, 0x0a, 0x62, 0x72, 0x61, 0x6e, 0x64, 0x5f,
	0x69, 0x63, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x09, 0x62, 0x72,
	0x61, 0x6e, 0x64, 0x49, 0x63, 0x6f, 0x6e, 0x88, 0x01, 0x01, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x62,
	0x72, 0x61, 0x6e, 0x64, 0x5f, 0x69, 0x63, 0x6f, 0x6e, 0x42, 0x12, 0x0a, 0x10, 0x5f, 0x70, 0x72,
	0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x62, 0x72, 0x6f, 0x6b, 0x65, 0x72, 0x22, 0x07, 0x0a,
	0x05, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x22, 0x0a, 0x0e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6d, 0x73, 0x67, 0x22, 0x95, 0x01, 0x0a, 0x09, 0x53,
	0x42, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x62, 0x72, 0x6f, 0x6b,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x62, 0x72, 0x6f,
	0x6b, 0x65, 0x72, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x12, 0x0a, 0x04, 0x6c, 0x61, 0x6e, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6c, 0x61, 0x6e, 0x67, 0x12, 0x3b, 0x0a, 0x14, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74,
	0x65, 0x64, 0x5f, 0x75, 0x69, 0x5f, 0x6c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x73, 0x18, 0x04, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x55, 0x49, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x52, 0x12,
	0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x55, 0x69, 0x4c, 0x61, 0x79, 0x6f, 0x75,
	0x74, 0x73, 0x22, 0xdd, 0x01, 0x0a, 0x08, 0x55, 0x49, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x12,
	0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x12, 0x19, 0x0a, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x48, 0x00, 0x52, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x88, 0x01, 0x01, 0x12, 0x1b,
	0x0a, 0x06, 0x62, 0x75, 0x74, 0x74, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01,
	0x52, 0x06, 0x62, 0x75, 0x74, 0x74, 0x6f, 0x6e, 0x88, 0x01, 0x01, 0x12, 0x17, 0x0a, 0x04, 0x77,
	0x61, 0x69, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x48, 0x02, 0x52, 0x04, 0x77, 0x61, 0x69,
	0x74, 0x88, 0x01, 0x01, 0x12, 0x19, 0x0a, 0x05, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x09, 0x48, 0x03, 0x52, 0x05, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x88, 0x01, 0x01, 0x12,
	0x1d, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x04, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x88, 0x01, 0x01, 0x42, 0x08,
	0x0a, 0x06, 0x5f, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x42, 0x09, 0x0a, 0x07, 0x5f, 0x62, 0x75, 0x74,
	0x74, 0x6f, 0x6e, 0x42, 0x07, 0x0a, 0x05, 0x5f, 0x77, 0x61, 0x69, 0x74, 0x42, 0x08, 0x0a, 0x06,
	0x5f, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65,
	0x6e, 0x74, 0x22, 0xe5, 0x01, 0x0a, 0x0a, 0x53, 0x42, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64,
	0x12, 0x25, 0x0a, 0x0e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x12, 0x51, 0x0a, 0x14, 0x61, 0x75, 0x74, 0x68, 0x65,
	0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x73, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x53, 0x42, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x13, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x6f, 0x64, 0x65, 0x73, 0x1a, 0x3e, 0x0a, 0x12, 0x41, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x6f, 0x64, 0x65,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x22, 0x65, 0x0a, 0x0a, 0x53, 0x41,
	0x4d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x18, 0x61, 0x75, 0x74, 0x68, 0x65,
	0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x5f, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x16, 0x61, 0x75, 0x74, 0x68, 0x65,
	0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x6f, 0x64, 0x65, 0x4e, 0x61, 0x6d,
	0x65, 0x22, 0x3e, 0x0a, 0x0b, 0x53, 0x41, 0x4d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x2f, 0x0a, 0x0e, 0x75, 0x69, 0x5f, 0x6c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x5f, 0x69, 0x6e,
	0x66, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x55, 0x49, 0x4c, 0x61, 0x79,
	0x6f, 0x75, 0x74, 0x52, 0x0c, 0x75, 0x69, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x49, 0x6e, 0x66,
	0x6f, 0x22, 0x5b, 0x0a, 0x09, 0x49, 0x41, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d,
	0x0a, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x2f, 0x0a,
	0x13, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f,
	0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x61, 0x75, 0x74, 0x68,
	0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x61, 0x74, 0x61, 0x22, 0x99,
	0x01, 0x0a, 0x0a, 0x49, 0x41, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a,
	0x06, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x12, 0x36, 0x0a, 0x09, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x6e,
	0x66, 0x6f, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x49, 0x41, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x1a, 0x3b, 0x0a,
	0x0d, 0x55, 0x73, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x32, 0xbb, 0x01, 0x0a, 0x03, 0x50,
	0x41, 0x4d, 0x12, 0x2b, 0x0a, 0x10, 0x41, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x42,
	0x72, 0x6f, 0x6b, 0x65, 0x72, 0x73, 0x12, 0x0a, 0x2e, 0x41, 0x42, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x0b, 0x2e, 0x41, 0x42, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x27, 0x0a, 0x0c, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x42, 0x72, 0x6f, 0x6b, 0x65, 0x72, 0x12,
	0x0a, 0x2e, 0x53, 0x42, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0b, 0x2e, 0x53, 0x42,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x35, 0x0a, 0x18, 0x53, 0x65, 0x6c, 0x65,
	0x63, 0x74, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x4d, 0x6f, 0x64, 0x65, 0x12, 0x0b, 0x2e, 0x53, 0x41, 0x4d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x0c, 0x2e, 0x53, 0x41, 0x4d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x27, 0x0a, 0x0c, 0x49, 0x73, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x12,
	0x0a, 0x2e, 0x49, 0x41, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0b, 0x2e, 0x49, 0x41,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0x29, 0x0a, 0x03, 0x4e, 0x53, 0x53, 0x12,
	0x22, 0x0a, 0x07, 0x54, 0x65, 0x73, 0x74, 0x4e, 0x53, 0x53, 0x12, 0x06, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x1a, 0x0f, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x42, 0x19, 0x5a, 0x17, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x75, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x64, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_authd_proto_rawDescOnce sync.Once
	file_authd_proto_rawDescData = file_authd_proto_rawDesc
)

func file_authd_proto_rawDescGZIP() []byte {
	file_authd_proto_rawDescOnce.Do(func() {
		file_authd_proto_rawDescData = protoimpl.X.CompressGZIP(file_authd_proto_rawDescData)
	})
	return file_authd_proto_rawDescData
}

var file_authd_proto_msgTypes = make([]protoimpl.MessageInfo, 14)
var file_authd_proto_goTypes = []interface{}{
	(*ABRequest)(nil),                     // 0: ABRequest
	(*ABResponse)(nil),                    // 1: ABResponse
	(*Empty)(nil),                         // 2: Empty
	(*StringResponse)(nil),                // 3: StringResponse
	(*SBRequest)(nil),                     // 4: SBRequest
	(*UILayout)(nil),                      // 5: UILayout
	(*SBResponse)(nil),                    // 6: SBResponse
	(*SAMRequest)(nil),                    // 7: SAMRequest
	(*SAMResponse)(nil),                   // 8: SAMResponse
	(*IARequest)(nil),                     // 9: IARequest
	(*IAResponse)(nil),                    // 10: IAResponse
	(*ABResponse_BrokerInfo)(nil),         // 11: ABResponse.BrokerInfo
	(*SBResponse_AuthenticationMode)(nil), // 12: SBResponse.AuthenticationMode
	nil,                                   // 13: IAResponse.UserInfoEntry
}
var file_authd_proto_depIdxs = []int32{
	11, // 0: ABResponse.brokers_infos:type_name -> ABResponse.BrokerInfo
	5,  // 1: SBRequest.supported_ui_layouts:type_name -> UILayout
	12, // 2: SBResponse.authentication_modes:type_name -> SBResponse.AuthenticationMode
	5,  // 3: SAMResponse.ui_layout_info:type_name -> UILayout
	13, // 4: IAResponse.user_info:type_name -> IAResponse.UserInfoEntry
	0,  // 5: PAM.AvailableBrokers:input_type -> ABRequest
	4,  // 6: PAM.SelectBroker:input_type -> SBRequest
	7,  // 7: PAM.SelectAuthenticationMode:input_type -> SAMRequest
	9,  // 8: PAM.IsAuthorized:input_type -> IARequest
	2,  // 9: NSS.TestNSS:input_type -> Empty
	1,  // 10: PAM.AvailableBrokers:output_type -> ABResponse
	6,  // 11: PAM.SelectBroker:output_type -> SBResponse
	8,  // 12: PAM.SelectAuthenticationMode:output_type -> SAMResponse
	10, // 13: PAM.IsAuthorized:output_type -> IAResponse
	3,  // 14: NSS.TestNSS:output_type -> StringResponse
	10, // [10:15] is the sub-list for method output_type
	5,  // [5:10] is the sub-list for method input_type
	5,  // [5:5] is the sub-list for extension type_name
	5,  // [5:5] is the sub-list for extension extendee
	0,  // [0:5] is the sub-list for field type_name
}

func init() { file_authd_proto_init() }
func file_authd_proto_init() {
	if File_authd_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_authd_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ABRequest); i {
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
		file_authd_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ABResponse); i {
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
		file_authd_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
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
		file_authd_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StringResponse); i {
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
		file_authd_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SBRequest); i {
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
		file_authd_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UILayout); i {
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
		file_authd_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SBResponse); i {
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
		file_authd_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SAMRequest); i {
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
		file_authd_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SAMResponse); i {
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
		file_authd_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IARequest); i {
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
		file_authd_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IAResponse); i {
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
		file_authd_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ABResponse_BrokerInfo); i {
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
		file_authd_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SBResponse_AuthenticationMode); i {
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
	file_authd_proto_msgTypes[0].OneofWrappers = []interface{}{}
	file_authd_proto_msgTypes[1].OneofWrappers = []interface{}{}
	file_authd_proto_msgTypes[5].OneofWrappers = []interface{}{}
	file_authd_proto_msgTypes[11].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_authd_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   14,
			NumExtensions: 0,
			NumServices:   2,
		},
		GoTypes:           file_authd_proto_goTypes,
		DependencyIndexes: file_authd_proto_depIdxs,
		MessageInfos:      file_authd_proto_msgTypes,
	}.Build()
	File_authd_proto = out.File
	file_authd_proto_rawDesc = nil
	file_authd_proto_goTypes = nil
	file_authd_proto_depIdxs = nil
}
