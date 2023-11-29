package main

/*
#cgo LDFLAGS: -ldl -lpam
#cgo CFLAGS: -I../
#include "utils.h"

*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/gdm"
)

// pamHandle allows to pass C.pam_handle_t to this package.
type pamHandle = *C.pam_handle_t

var PAM_SUCCESS int = C.PAM_SUCCESS
var GDM_PAM_EXTENSION_CUSTOM_JSON string = C.GDM_PAM_EXTENSION_CUSTOM_JSON

func initPamHandle(serviceName string, user string, servicePath string) (pamHandle, error) {
	var cError *C.char
	cServiceName := C.CString(serviceName)
	defer C.free(unsafe.Pointer(cServiceName))
	cUser := C.CString(user)
	defer C.free(unsafe.Pointer(cUser))
	cServicePath := C.CString(servicePath)
	defer C.free(unsafe.Pointer(cServicePath))
	if pamh := C.init_handle(cServiceName, cUser, cServicePath, &cError); pamh != nil {
		return pamh, nil
	}

	return nil, fmt.Errorf("PAM handle initialization failure %s",
		C.GoString(cError))
}

func destroyPamHandle(pamh pamHandle, pamStatus int) (int, error) {
	advertisePamExtensions([]string{})
	if ret := C.pam_end(pamh, C.int(pamStatus)); ret != 0 {
		return int(ret), fmt.Errorf("pam stop failure: %s",
			C.GoString(C.pam_strerror(pamh, ret)))
	}
	return 0, nil
}

func advertisePamExtensions(extensions []string) {
	if len(extensions) == 0 {
		C.advertise_supported_pam_extensions(nil, 0)
		return
	}
	cArray := make([]*C.char, 0, len(extensions))
	for _, extension := range extensions {
		cExtension := C.CString(extension)
		defer C.free(unsafe.Pointer(cExtension))
		cArray = append(cArray, cExtension)
	}
	C.advertise_supported_pam_extensions(&cArray[0], C.size_t(len(extensions)))
}

func authenticate(pamh pamHandle) (int, error) {
	if ret := C.pam_authenticate(pamh, 0); ret != 0 {
		return int(ret), fmt.Errorf("authentication failure: %s",
			C.GoString(C.pam_strerror(pamh, ret)))
	}
	return 0, nil
}

//export go_handle_pam_message
func go_handle_pam_message(message *C.struct_pam_message, reply **C.uchar) C.int {
	var handler PamMessagesHandler
	switch message.msg_style {
	case C.PAM_PROMPT_ECHO_OFF:
		handler = defaultHandlers.promptEchoOff
	case C.PAM_PROMPT_ECHO_ON:
		handler = defaultHandlers.promptEchoOn
	case C.PAM_ERROR_MSG:
		handler = defaultHandlers.errorMsg
	case C.PAM_TEXT_INFO:
		handler = defaultHandlers.info
	case C.PAM_RADIO_TYPE:
		// TODO: Not implemented
	case C.PAM_BINARY_PROMPT:
		retCode, bytes := handleBinaryProtocol(message)
		*reply = (*C.uchar)(C.CBytes(bytes))
		return C.int(retCode)
	}

	if handler != nil {
		out, err := handler(C.GoString(message.msg))
		if err != nil {
			log.Error(context.TODO(), err)
			return C.PAM_AUTH_ERR
		}

		*reply = (*C.uchar)(C.CBytes([]byte(out)))
		return C.PAM_SUCCESS
	}

	return C.PAM_AUTHINFO_UNAVAIL
}

func formatAuthDJSonProtoReply(reply []byte) []byte {
	response := C.GdmPamExtensionJSONProtocol{}
	cProtoName := C.CString(gdm.JSONProtoName)
	defer C.free(unsafe.Pointer(cProtoName))

	C.gdm_private_string_response_init(&response, cProtoName,
		C.uint(gdm.JSONProtoVersion))

	// These are stolen as will be owned by the module
	response.json = C.CString(string(reply))
	fmt.Println("ALLOCATED LOADER", unsafe.Pointer(response.json))
	return C.GoBytes(unsafe.Pointer(&response), C.int(unsafe.Sizeof(response)))
}

func handleBinaryProtocol(message *C.struct_pam_message) (int, []byte) {
	var proto *C.char
	var version C.int
	value := C.get_gdm_string_protocol_value(message, &proto, &version)
	if proto == nil || version <= 0 || value == nil {
		return C.PAM_AUTHINFO_UNAVAIL, nil
	}

	log.Debugf(context.TODO(), "Got protocol %s, version %d, value %s",
		C.GoString(proto), version, C.GoString(value))

	if C.GoString(proto) == gdm.JSONProtoName && uint(version) == gdm.JSONProtoVersion {
		retValue, err := handleAuthDJsonProto(C.GoBytes(unsafe.Pointer(value),
			C.int(C.strlen(value))))
		if err != nil {
			log.Error(context.TODO(), err)
			return C.PAM_BUF_ERR, nil
		}

		return C.PAM_SUCCESS, retValue
	}

	return C.PAM_AUTHINFO_UNAVAIL, nil
}

func handleAuthDJsonProto(jsonValue []byte) ([]byte, error) {
	log.Debugf(context.TODO(), "Handling value %s", string(jsonValue))
	gdmData, err := gdm.NewDataFromJSON(jsonValue)
	if err != nil {
		return nil, err
	}

	if defaultHandlers.gdmData == nil {
		return nil, errors.New("gdm data handler not implemented")
	}

	outGdmData, err := defaultHandlers.gdmData(gdmData)
	if err != nil {
		return nil, err
	}

	return marshalGdmDataToAuthdJSon(outGdmData)
}

func marshalGdmDataToAuthdJSon(gdmData *gdm.Data) ([]byte, error) {
	if gdmData == nil {
		gdmData = &gdm.Data{}
	}
	bytes, err := gdmData.JSON()
	if err != nil {
		return nil, err
	}

	log.Debugf(context.TODO(), "Reply converted to JSON: %s", string(bytes))

	return formatAuthDJSonProtoReply(bytes), nil
}
