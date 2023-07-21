package main

/*
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *string_from_argv(int i, char **argv) {
  return strdup(argv[i]);
}

char *get_user(pam_handle_t *pamh) {
  if (!pamh)
    return NULL;
  int pam_err = 0;
  const char *user;
  if ((pam_err = pam_get_item(pamh, PAM_USER, (const void**)&user)) != PAM_SUCCESS)
    return NULL;
  return strdup(user);
}

char *set_user(pam_handle_t *pamh, char *username) {
  if (!pamh)
    return NULL;
  int pam_err = 0;
  if ((pam_err = pam_set_item(pamh, PAM_USER, (const void*)username)) != PAM_SUCCESS)
    return NULL;
  return NULL;
}

const char *
get_module_name (pam_handle_t *pamh)
{
  const char *module_name;

  if (pam_get_item(pamh, PAM_SERVICE, (const void **) &module_name) != PAM_SUCCESS)
    return NULL;

  return module_name;
}

static struct pam_response *
send_msg (pam_handle_t *pamh, const char *msg, int style)
{
  const struct pam_message pam_msg = {
    .msg_style = style,
    .msg = msg,
  };
  const struct pam_conv *pc;
  struct pam_response *resp;

  if (pam_get_item (pamh, PAM_CONV, (const void **) &pc) != PAM_SUCCESS)
    return NULL;

  if (!pc || !pc->conv)
    return NULL;

  if (pc->conv (1, (const struct pam_message *[]){ &pam_msg }, &resp,
                pc->appdata_ptr) != PAM_SUCCESS)
    return NULL;

  return resp;
}

*/
import "C"

import (
	"fmt"
	"unsafe"
)

// pamHandle allows to pass C.pam_handle_t to this package.
type pamHandle = *C.pam_handle_t

type PamPrompt int

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
		s := C.string_from_argv(C.int(i), argv)
		defer C.free(unsafe.Pointer(s))
		r = append(r, C.GoString(s))
	}
	return r
}

// mockPamUser mocks the PAM user item in absence of pamh for manual testing.
var mockPamUser = "user1" // TODO: remove assignement once ok with debugging

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
