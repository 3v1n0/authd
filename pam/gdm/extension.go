package gdm

/*
#include "extension.h"
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"

	"github.com/msteinert/pam"
	"github.com/ubuntu/authd/internal/log"
)

const (
	// PamExtensionPrivateString is the gdm PAM extension for passing string values.
	PamExtensionPrivateString = C.GDM_PAM_EXTENSION_PRIVATE_STRING
	// StringProtoName is the gdm private string protocol name.
	StringProtoName = "com.ubuntu.authd.gdm-JSON"
	// StringProtoVersion is the gdm private string protocol version.
	StringProtoVersion = uint(1)
)

func init() {
	var msg stringProtoMessage
	if unsafe.Sizeof(msg) != C.GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE {
		panic(fmt.Sprintf("unexpected request size: %v vs %v", unsafe.Sizeof(msg),
			C.GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE))
	}

	if uintptr(len(StringProtoName)) >= unsafe.Sizeof(msg.protocol_name) {
		panic(fmt.Sprintf("Protocol version '%s' exceeds maximum size of %d",
			StringProtoName, unsafe.Sizeof(msg.protocol_name)))
	}
}

// IsPamExtensionSupported returns if the provided extension is supported
func IsPamExtensionSupported(extension string) bool {
	cExtension := C.CString(extension)
	defer C.free(unsafe.Pointer(cExtension))
	return bool(C.is_gdm_pam_extension_supported(cExtension))
}

// AdvertisePamExtensions enable GDM pam extensions in the current binary.
func AdvertisePamExtensions(extensions []string) {
	if len(extensions) == 0 {
		C.gdm_extensions_advertise_supported(nil, 0)
		return
	}
	cArray := make([]*C.char, 0, len(extensions))
	for _, extension := range extensions {
		cExtension := C.CString(extension)
		defer C.free(unsafe.Pointer(cExtension))
		cArray = append(cArray, cExtension)
	}
	C.gdm_extensions_advertise_supported(&cArray[0], C.size_t(len(extensions)))
}

type stringProtoMessage = C.GdmPamExtensionStringProtocol

func newStringProtoMessage(value []byte) *stringProtoMessage {
	// We do manual memory management here, instead of returning a go-allocated
	// structure, so that we can just use a single finalizer function for both
	// request and response messages.
	var msg *stringProtoMessage
	msg = (*stringProtoMessage)(C.malloc(C.ulong(unsafe.Sizeof(*msg))))
	msg.init(StringProtoName, StringProtoVersion, value)
	return msg
}

func (msg *stringProtoMessage) init(protoName string, protoVersion uint, value []byte) {
	cProto := C.CString(protoName)
	defer C.free(unsafe.Pointer(cProto))
	cValue := (*C.char)(nil)
	if value != nil {
		// We don't use string() here to avoid an extra copy, so we need to
		// add ourself the final null byte to the string.
		// Also the newly allocated C bytes are stolen, since they will be
		// owned by the stringProtoMessage now. So it's up to it to release
		// them via finalizer functions.
		cValue = (*C.char)(C.CBytes(append(value, 0x00)))
	}
	C.gdm_private_string_request_init(msg, cProto, C.uint(protoVersion), cValue)
}

func (msg *stringProtoMessage) release() {
	if msg == nil {
		return
	}

	C.free(unsafe.Pointer(msg.value))
	C.free(unsafe.Pointer(msg))
}

func (msg *stringProtoMessage) encode() pam.BinaryPointer {
	return pam.BinaryPointer(msg)
}

func (msg *stringProtoMessage) toBytes() []byte {
	return C.GoBytes(unsafe.Pointer(msg), (C.int)(unsafe.Sizeof(*msg)))
}

func (msg *stringProtoMessage) toPointer() pam.BinaryPointer {
	return pam.BinaryPointer(C.CBytes(msg.toBytes()))
}

//	func stringProtoMessagePointerFinalizer(ptr pam.BinaryPointer) {
//		if ptr == nil {
//			return
//		}
//		msg := (*stringProtoMessage)(ptr)
//		C.free(unsafe.Pointer(msg.value))
//	}
// func stringProtoMessagePointerFinalizer(ptr pam.BinaryPointer) {
// 	(*stringProtoMessage)(ptr).release()
// }

// func stringProtoMessageReplyPointerFinalizer(ptr pam.BinaryPointer) {
// 	if ptr == nil {
// 		return
// 	}
// 	msg := (*stringProtoMessage)(ptr)
// 	C.free(unsafe.Pointer(msg.value))
// 	C.free(unsafe.Pointer(msg))
// }

// NewBinaryStringProtoRequest returns a new pam.BinaryConvRequest from the
// provided data.
func NewBinaryStringProtoRequest(data []byte) *pam.BinaryConvRequest {
	request := newStringProtoMessage(data)
	log.Debugf(context.TODO(), "Sending to gdm %s", string(data))
	return pam.NewBinaryConvRequest(request.encode(),
		func(ptr pam.BinaryPointer) { (*stringProtoMessage)(ptr).release() })
}

func decodeStringProtoMessage(response pam.BinaryPointer) ([]byte, error) {
	fmt.Println("Decoding ptr", response)
	reply := (*stringProtoMessage)(response)

	protoName := C.GoString((*C.char)(unsafe.Pointer(&reply.protocol_name)))
	if protoName != StringProtoName ||
		uint(reply.version) != StringProtoVersion {
		return nil, fmt.Errorf("protocol name or version mismatch: got %s v%d, expected %s v%d",
			protoName, reply.version, StringProtoName, StringProtoVersion)
	}

	if reply.value == nil {
		return nil, nil
	}

	return C.GoBytes(unsafe.Pointer(reply.value),
		C.int(C.strlen(reply.value))), nil
}
