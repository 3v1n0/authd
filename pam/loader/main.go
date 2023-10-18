package main

/*
#cgo LDFLAGS: -ldl -lpam
#cgo CFLAGS: -I../
#include "utils.h"
void __lsan_do_leak_check(void);
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/gdm"
)

// pamHandle allows to pass C.pam_handle_t to this package.
type pamHandle = *C.pam_handle_t

// stringToConstC gets a const char from a GO String
func stringToConstC(s string) *C.char {
	return (*C.char)(unsafe.Pointer(unsafe.StringData(s)))
}

//export go_handle_pam_message
func go_handle_pam_message(message *C.struct_pam_message, reply **C.uchar) C.int {
	switch message.msg_style {
	case C.PAM_PROMPT_ECHO_OFF:
		return C.PAM_AUTHINFO_UNAVAIL
	case C.PAM_PROMPT_ECHO_ON:
		return C.PAM_AUTHINFO_UNAVAIL
	case C.PAM_ERROR_MSG:
		return C.PAM_AUTHINFO_UNAVAIL
	case C.PAM_TEXT_INFO:
		return C.PAM_AUTHINFO_UNAVAIL
	case C.PAM_RADIO_TYPE:
		return C.PAM_AUTHINFO_UNAVAIL
	case C.PAM_BINARY_PROMPT:
		retcode, retbytes := handleBinaryProtocol(message)
		*reply = (*C.uchar)(C.CBytes(retbytes))
		return C.int(retcode)
	}
	return C.PAM_AUTHINFO_UNAVAIL
}

func formatAuthDJSonProtoReply(reply string) []byte {
	cReply := C.CString(reply)
	defer C.free(unsafe.Pointer(cReply))
	cProtoName := C.CString(gdm.ProtoName)
	defer C.free(unsafe.Pointer(cProtoName))
	cPamReply := (*C.char)(nil)
	defer C.free(unsafe.Pointer(cPamReply))
	var cPamReplySize C.size_t = 0

	C.format_gdm_string_protocol_reply(cProtoName, C.int(gdm.ProtoVersion),
		cReply, &cPamReply, &cPamReplySize)
	if cPamReply == nil {
		return []byte{}
	}
	formattedReply := C.GoBytes(unsafe.Pointer(cPamReply), C.int(cPamReplySize))
	log.Debugf(context.TODO(), "Formatted reply is %v", []byte(formattedReply))
	return formattedReply
}

func handleAuthDJsonProto(jsonValue string) ([]byte, error) {
	var gdmData gdm.Data
	err := json.Unmarshal([]byte(jsonValue), &gdmData)
	if err != nil {
		return []byte{}, err
	}

	log.Debugf(context.TODO(), "Handling authd protocol: %v", gdmData)

	bytes, err := json.Marshal(gdm.Data{
		Type: "hello",
		Data: map[string]any{"version": gdm.ProtoWireVersion},
	})
	if err != nil {
		return []byte{}, err
	}

	return formatAuthDJSonProtoReply(string(bytes)), nil
}

func handleBinaryProtocol(message *C.struct_pam_message) (int, []byte) {
	var proto *C.char
	var version C.int
	value := C.get_gdm_string_protocol_value(message, &proto, &version)
	if proto == nil || version <= 0 || value == nil {
		return C.PAM_AUTHINFO_UNAVAIL, []byte{}
	}

	log.Debugf(context.TODO(), "Got protocol %s, version %d, value %s",
		C.GoString(proto), version, C.GoString(value))

	if C.GoString(proto) == gdm.ProtoName && int(version) == gdm.ProtoVersion {
		retValue, err := handleAuthDJsonProto(C.GoString(value))
		if err != nil {
			log.Error(context.TODO(), err)
			return C.PAM_BUF_ERR, []byte{}
		}

		return C.PAM_SUCCESS, retValue
	}

	return C.PAM_AUTHINFO_UNAVAIL, []byte{}
}

func initPamHandle(serviceName string, user string, servicePath string) pamHandle {
	return C.init_handle(C.CString(serviceName),
		C.CString(user), C.CString(servicePath))
}

func authenticate(pamh pamHandle) int {
	return int(C.pam_authenticate(pamh, 0))
}

func advertisePamExtensions(extensions []string) {
	cArray := make([]*C.char, 0, len(extensions))
	for _, extension := range extensions {
		cArray = append(cArray, C.CString(extension))
	}
	C.advertise_supported_pam_extensions(&cArray[0])
}

func loadModule() int {
	// TODO: Add option to simulate different loading types
	log.SetLevel(log.DebugLevel)

	servicePath, err := os.MkdirTemp(os.TempDir(), "test-pam-loader-*")
	if err != nil {
		log.Errorf(context.TODO(), "Can't create service path %v", err)
		return 1
	}
	defer os.RemoveAll(servicePath)

	libPath := filepath.Join(servicePath, "libpam_authd.so")
	log.Debugf(context.TODO(), "Compiling module at %s", libPath)
	_, currentFile, _, ok := runtime.Caller(1)
	if !ok {
		log.Errorf(context.TODO(), "Can't get current binary path")
		return 1
	}
	// #nosec:G204 - we control the command arguments in tests
	out, err := exec.Command("go", "build", "-C", filepath.Join(
		filepath.Dir(currentFile), ".."), "-buildmode=c-shared", "-asan", "-o",
		libPath).CombinedOutput()
	if err != nil {
		log.Errorf(context.TODO(), "Can't build pam module %v: %s", err, out)
		return 1
	}

	serviceName := "module-loader"
	serviceFile := filepath.Join(servicePath, serviceName)
	log.Debugf(context.TODO(), "Creating service file at %s", serviceFile)

	err = os.WriteFile(serviceFile,
		[]byte(fmt.Sprintf("auth requisite %s", libPath)),
		0600)

	if err != nil {
		log.Errorf(context.TODO(), "Can't create service file %v", err)
		return 1
	}

	advertisePamExtensions([]string{C.GDM_PAM_EXTENSION_PRIVATE_STRING})
	pamh := initPamHandle(serviceFile, "", servicePath)
	if pamh == nil {
		log.Error(context.TODO(), "Can't create PAM handler")
		return 1
	}

	log.Debug(context.TODO(), "PAM Handler created")

	defer func() {
		runtime.GC()
		time.Sleep(0.3 * time.Second)
		C.__lsan_do_leak_check()
	}()

	return int(C.pam_end(pamh, C.int(authenticate(pamh))))
}

func main() {
	os.Exit(loadModule())
}
