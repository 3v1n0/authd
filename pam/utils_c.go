package main

/*
#include "pam-utils.h"
*/
import "C"

import (
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
	for i := 0; i < int(argc); i++ {
		s := C.argv_string_get(argv, C.uint(i))
		defer C.free(unsafe.Pointer(s))
		r = append(r, C.GoString(s))
	}
	return r
}

// mockPamUser mocks the PAM user item in absence of pamh for manual testing.
var mockPamUser = "user1" // TODO: remove assignement once ok with debugging

// stringToConstC gets a const char from a GO String
func stringToConstC(s string) *C.char {
	return (*C.char)(unsafe.Pointer(unsafe.StringData(s)))
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

	C.set_user(pamh, stringToConstC(username))
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
	pamConvMutex.Lock()
	defer pamConvMutex.Unlock()
	cResponse := C.send_msg(pamh, stringToConstC(prompt), C.int(kind))
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
