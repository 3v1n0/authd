package gdm

/*
#include "extensions.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/msteinert/pam"
)

const (
	// PamExtensionPrivateString is the gdm PAM extension for passing string values
	PamExtensionPrivateString = C.GDM_PAM_EXTENSION_PRIVATE_STRING
)

// IsPamExtensionSupported returns if the provided extension is supported
func IsPamExtensionSupported(extension string) bool {
	cExtension := C.CString(extension)
	defer C.free(unsafe.Pointer(cExtension))
	return bool(C.is_gdm_extension_supported(cExtension))
}

type stringRequest = C.GdmPamExtensionStringProtocol

func newStringRequest(value string) *stringRequest {
	req := C.GdmPamExtensionStringProtocol{}

	cProto := C.CString(ProtoName)
	defer C.free(unsafe.Pointer(cProto))
	cValue := C.CString(value)
	C.gdm_private_string_request_init(&req, cProto, C.int(ProtoVersion), cValue)
	runtime.SetFinalizer(&req, func(*stringRequest) {
		C.free(unsafe.Pointer(cValue))
	})
	return &req
}

func (req *stringRequest) encode() []byte {
	if unsafe.Sizeof(*req) != C.GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE {
		panic(fmt.Sprintf("unexpected request size: %v vs %v", unsafe.Sizeof(*req),
			C.GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE))
	}
	return C.GoBytes(unsafe.Pointer(req),
		C.GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE)
}

func decodeResponse(response pam.BinaryPointer) ([]byte, error) {
	reply := (*C.GdmPamExtensionStringProtocol)(response)

	defer C.free(unsafe.Pointer(reply.value))
	defer C.free(unsafe.Pointer(reply))

	if C.GoString((*C.char)(unsafe.Pointer(&reply.protocol_name))) != ProtoName ||
		int(reply.version) != ProtoVersion {
		return nil, errors.New("Protocol name or version mismatch")
	}

	return []byte(C.GoString(reply.value)), nil
}
