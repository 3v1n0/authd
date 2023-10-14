package main

import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/msteinert/pam"
)

// PamModuleTransactionDummy is an implementation of PamModuleTransaction for
// testing purposes.
type PamModuleTransactionDummy struct {
	Items       map[pam.Item]string
	Env         map[string]string
	Data        map[string]any
	convHandler pam.ConversationHandler
}

// NewPamModuleTransactionDummy returns a new PamModuleTransactionDummy.
func NewPamModuleTransactionDummy(convHandler pam.ConversationHandler) PamModuleTransaction {
	return &PamModuleTransactionDummy{
		convHandler: convHandler,
	}
}

// SetItem sets a PAM information item.
func (m *PamModuleTransactionDummy) SetItem(item pam.Item, value string) error {
	if m.Items == nil {
		m.Items = make(map[pam.Item]string)
	}

	m.Items[item] = value
	return nil
}

// GetItem retrieves a PAM information item.
func (m *PamModuleTransactionDummy) GetItem(item pam.Item) (string, error) {
	if m.Items == nil {
		return "", nil
	}
	return m.Items[item], nil
}

// PutEnv adds or changes the value of PAM environment variables.
//
// NAME=value will set a variable to a value.
// NAME= will set a variable to an empty value.
// NAME (without an "=") will delete a variable.
func (m *PamModuleTransactionDummy) PutEnv(nameVal string) error {
	if m.Env == nil {
		m.Env = make(map[string]string)
	}

	env, value, found := strings.Cut(nameVal, "=")
	if !found {
		delete(m.Env, env)
		return nil
	}
	if env == "" {
		return pam.BadItem
	}
	m.Env[env] = value
	return nil
}

// GetEnv is used to retrieve a PAM environment variable.
func (m *PamModuleTransactionDummy) GetEnv(name string) string {
	if m.Env == nil {
		return ""
	}

	return m.Env[name]
}

// GetEnvList returns a copy of the PAM environment as a map.
func (m *PamModuleTransactionDummy) GetEnvList() (map[string]string, error) {
	if m.Env == nil {
		m.Env = make(map[string]string)
	}
	return m.Env, nil
}

// GetUser is similar to GetItem(User), but it would start a conversation if
// no user is currently set in PAM.
func (m *PamModuleTransactionDummy) GetUser(prompt string) (string, error) {
	if user, err := m.GetItem(pam.User); err != nil {
		return "", err
	} else if user != "" {
		return user, nil
	}

	resp, err := m.StartStringConv(pam.PromptEchoOn, prompt)
	if err != nil {
		return "", err
	}

	return resp.Response(), nil
}

// SetData allows to save any value in the module data that is preserved
// during the whole time the module is loaded.
func (m *PamModuleTransactionDummy) SetData(key string, data any) error {
	if m.Data == nil {
		m.Data = make(map[string]any)
	}

	m.Data[key] = data
	return nil
}

// GetData allows to get any value from the module data saved using SetData
// that is preserved across the whole time the module is loaded.
func (m *PamModuleTransactionDummy) GetData(key string) (any, error) {
	if m.Data == nil {
		return nil, pam.NoModuleData
	}

	data, found := m.Data[key]
	if found {
		return data, nil
	}
	return nil, pam.NoModuleData
}

// DummyStringResponse is a simple implementation of pam.StringConvResponse.
type DummyStringResponse struct {
	style   pam.Style
	content string
}

// Style returns the conversation style of the DummyStringResponse.
func (s DummyStringResponse) Style() pam.Style {
	return s.style
}

// Response returns the string response of the DummyStringResponse.
func (s DummyStringResponse) Response() string {
	return s.content
}

// DummyBinaryResponse is an implementation of pam.BinaryConvResponse.
type DummyBinaryResponse struct {
	ptr pam.BinaryPointer
}

// Style returns the response style for the response, so always BinaryPrompt.
func (b DummyBinaryResponse) Style() pam.Style {
	return pam.BinaryPrompt
}

// Data returns the response native pointer, it's up to the protocol to parse
// it accordingly.
func (b DummyBinaryResponse) Data() pam.BinaryPointer {
	return b.ptr
}

// Decode decodes the binary data using the provided decoder function.
func (b DummyBinaryResponse) Decode(decoder pam.BinaryDecoder) (
	[]byte, error) {
	if decoder == nil {
		return nil, errors.New("nil decoder provided")
	}
	return decoder(b.ptr)
}

// StartStringConv starts a text-based conversation using the provided style
// and prompt.
func (m *PamModuleTransactionDummy) StartStringConv(style pam.Style, prompt string) (
	pam.StringConvResponse, error) {
	switch style {
	case pam.BinaryPrompt:
		return nil, pam.NewTransactionError(errors.New("Binary style is not supported"),
			pam.ConvErr)
	}

	res, err := m.StartConv(pam.NewStringConvRequest(style, prompt))
	if err != nil {
		return nil, err
	}

	if stringRes, ok := res.(pam.StringConvResponse); ok {
		return stringRes, nil
	}

	return nil, pam.NewTransactionError(
		errors.New("Can't convert to pam.StringConvResponse"), pam.ConvErr)
}

// StartStringConvf allows to start string conversation with formatting support.
func (m *PamModuleTransactionDummy) StartStringConvf(style pam.Style, format string, args ...interface{}) (
	pam.StringConvResponse, error) {
	return m.StartStringConv(style, fmt.Sprintf(format, args...))
}

// StartBinaryConv starts a binary conversation using the provided bytes.
func (m *PamModuleTransactionDummy) StartBinaryConv(bytes []byte) (
	pam.BinaryConvResponse, error) {
	res, err := m.StartConv(pam.NewBinaryConvRequestFromBytes(bytes))
	if err != nil {
		return nil, err
	}

	if binaryRes, ok := res.(pam.BinaryConvResponse); ok {
		return binaryRes, nil
	}

	return nil, pam.NewTransactionError(
		errors.New("Can't convert to pam.BinaryConvResponse"), pam.ConvErr)
}

// StartConv initiates a PAM conversation using the provided ConvRequest.
func (m *PamModuleTransactionDummy) StartConv(req pam.ConvRequest) (
	pam.ConvResponse, error) {
	if resp, err := m.StartConvMulti([]pam.ConvRequest{req}); err != nil {
		return nil, err
	} else if len(resp) != 1 {
		return nil, pam.NewTransactionError(errors.New("not enough values returned"),
			pam.ConvErr)
	} else {
		return resp[0], nil
	}
}

// StartConvMulti initiates a PAM conversation with multiple ConvRequest's.
func (m *PamModuleTransactionDummy) StartConvMulti(requests []pam.ConvRequest) (
	[]pam.ConvResponse, error) {
	if len(requests) == 0 {
		return nil, pam.NewTransactionError(errors.New("no requests defined"),
			pam.ConvErr)
	}

	goReplies := make([]pam.ConvResponse, 0, len(requests))
	for _, req := range requests {
		msgStyle := req.Style()
		switch msgStyle {
		case pam.PromptEchoOff:
			fallthrough
		case pam.PromptEchoOn:
			fallthrough
		case pam.ErrorMsg:
			fallthrough
		case pam.TextInfo:
			if m.convHandler == nil {
				return nil, pam.NewTransactionError(
					fmt.Errorf(
						"no conversation handler provided for style %v", msgStyle),
					pam.ConvErr)
			}
			reply, err := m.convHandler.RespondPAM(msgStyle,
				req.(pam.StringConvRequest).Prompt())
			if err != nil {
				return nil, err
			}
			goReplies = append(goReplies, DummyStringResponse{
				msgStyle,
				reply,
			})
		case pam.BinaryPrompt:
			handler, ok := m.convHandler.(pam.BinaryConversationHandler)
			if handler == nil || !ok {
				return nil, pam.NewTransactionError(
					errors.New("no binary handler provided"),
					pam.ConvErr)
			}
			reply, err := handler.RespondPAMBinary(
				req.(pam.BinaryConvRequest).Pointer())
			if err != nil {
				return nil, err
			}
			goReplies = append(goReplies,
				DummyBinaryResponse{pam.BinaryPointer(&reply)})
		default:
			return nil, pam.NewTransactionError(
				fmt.Errorf(
					"unsupported conversation type %v", msgStyle),
				pam.ConvErr)
		}
	}

	return goReplies, nil
}

func getBinaryFromPointer(ptr pam.BinaryPointer, length int) []byte {
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length))
}
