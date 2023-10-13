package main

/*
#include "pam-utils.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// pamHandle allows to pass C.pam_handle_t to this package.
type pamHandle = *C.pam_handle_t

type PamPrompt int

var pamConvMutex = sync.Mutex{}

const (
	PamPromptEchoOff PamPrompt = 1
	PamPromptEchoOn  PamPrompt = 2
	PamPromptError   PamPrompt = 3
	PamPromptInfo    PamPrompt = 4
	PamPromptRadio   PamPrompt = 5
	PamPromptBinary  PamPrompt = 7
)

// sliceFromArgv returns a slice of strings given to the PAM module.
func sliceFromArgv(argc C.int, argv **C.char) []string {
	r := make([]string, 0, argc)
	for _, s := range unsafe.Slice(argv, argc) {
		r = append(r, C.GoString(s))
	}
	return r
}

// mockPamUser mocks the PAM user item in absence of pamh for manual testing.
var mockPamUser = "user1" // TODO: remove assignement once ok with debugging

func isGdmPamExtensionSupported(extension string) bool {
	cExtension := C.CString(extension)
	defer C.free(unsafe.Pointer(cExtension))
	return bool(C.is_gdm_extension_supported(cExtension))
}

// getPAMUser returns the user from PAM.
func getPAMUser(pamh *C.pam_handle_t) string {
	if pamh == nil {
		return mockPamUser
	}
	cUsername := C.get_user(pamh)
	if cUsername == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cUsername))
	return C.GoString(cUsername)
}

// setPAMUser set current user to PAM.
func setPAMUser(pamh *C.pam_handle_t, username string) {
	if pamh == nil {
		mockPamUser = username
		return
	}
	cUsername := C.CString(username)
	defer C.free(unsafe.Pointer(cUsername))

	C.set_user(pamh, cUsername)
}

// getPAMUser returns the user from PAM.
func promptForPAMUser(pamh *C.pam_handle_t, prompt string) string {
	if pamh == nil {
		return mockPamUser
	}
	pamConvMutex.Lock()
	defer pamConvMutex.Unlock()
	fmt.Println("Asking for username to pam...")
	cUsername := C.prompt_for_username(pamh, C.CString(prompt))
	fmt.Println("Got username", cUsername, "value %s", C.GoString(cUsername))
	if cUsername == nil {
		return ""
	}
	return C.GoString(cUsername)
}

// getModuleName gets the current PAM module name.
func getModuleName(pamh pamHandle) (string, error) {
	cModuleName := C.get_module_name(pamh)
	if cModuleName == nil {
		return "", fmt.Errorf("no module name found")
	}
	return C.GoString(cModuleName), nil
}

// pamConv starts a pam conversation of type PamPrompt
func pamConv(pamh pamHandle, prompt string, kind PamPrompt) (string, error) {
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))
	pamConvMutex.Lock()
	defer pamConvMutex.Unlock()
	cResponse := C.send_msg(pamh, cPrompt, C.int(kind))
	if cResponse == nil {
		return "", fmt.Errorf("conversation with PAM application failed")
	}
	defer C.free(unsafe.Pointer(cResponse))
	return C.GoString(cResponse.resp), nil
}

// sendInfo sends an info message to PAM
func sendInfo(pamh pamHandle, prompt string) error {
	_, err := pamConv(pamh, "INFO: "+prompt, PamPromptInfo)
	return err
}

// sendInfof sends an info message to PAM with formatting support
func sendInfof(pamh pamHandle, format string, args ...interface{}) error {
	return sendInfo(pamh, fmt.Sprintf(format, args...))
}

// sendError sends an error message to PAM
func sendError(pamh pamHandle, prompt string) error {
	_, err := pamConv(pamh, "ERROR: "+prompt, PamPromptError)
	return err
}

// sendErrorf sends an error message  to PAM with formatting support
func sendErrorf(pamh pamHandle, format string, args ...interface{}) error {
	return sendInfo(pamh, fmt.Sprintf(format, args...))
}

// requestInput requests for input text to PAM client
func requestInput(pamh pamHandle, prompt string) (string, error) {
	return pamConv(pamh, prompt+": ", PamPromptEchoOn)
}

// requestSecret requests for input secret to PAM client
func requestSecret(pamh pamHandle, prompt string) (string, error) {
	return pamConv(pamh, prompt+": ", PamPromptEchoOff)
}

// sendGdmAuthdProtoRequest sends an authd request to GDM
func sendGdmAuthdProtoData(pamh pamHandle, data string) (string, error) {
	cProto := C.CString("authd-json")
	defer C.free(unsafe.Pointer(cProto))
	cData := C.CString(data)
	defer C.free(unsafe.Pointer(cData))
	cError := (*C.char)(nil)
	defer C.free(unsafe.Pointer(cError))

	pamConvMutex.Lock()
	defer pamConvMutex.Unlock()
	cReply := C.gdm_private_string_protocol_send(pamh, cProto, 1, cData, &cError)
	if cReply == nil {
		return "", errors.New(C.GoString(cError))
	}

	defer C.free(unsafe.Pointer(cReply))
	return C.GoString(cReply), nil
}
