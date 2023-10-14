package pam_test

import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/msteinert/pam"
)

// ModuleTransactionDummy is an implementation of PamModuleTransaction for
// testing purposes.
type ModuleTransactionDummy struct {
	Items       map[pam.Item]string
	Env         map[string]string
	Data        map[string]any
	convHandler pam.ConversationHandler
}

// NewModuleTransactionDummy returns a new PamModuleTransactionDummy.
func NewModuleTransactionDummy(convHandler pam.ConversationHandler) pam.ModuleTransaction {
	return &ModuleTransactionDummy{
		convHandler: convHandler,
	}
}

// InvokeHandler is called by the C code to invoke the proper handler.
func (m *ModuleTransactionDummy) InvokeHandler(handler pam.ModuleHandlerFunc,
	flags pam.Flags, args []string) (pam.Status, error) {
	return pam.Abort, pam.Abort
}

// SetItem sets a PAM information item.
func (m *ModuleTransactionDummy) SetItem(item pam.Item, value string) error {
	if m.Items == nil {
		m.Items = make(map[pam.Item]string)
	}

	m.Items[item] = value
	return nil
}

// GetItem retrieves a PAM information item.
func (m *ModuleTransactionDummy) GetItem(item pam.Item) (string, error) {
	return m.Items[item], nil
}

// PutEnv adds or changes the value of PAM environment variables.
//
// NAME=value will set a variable to a value.
// NAME= will set a variable to an empty value.
// NAME (without an "=") will delete a variable.
func (m *ModuleTransactionDummy) PutEnv(nameVal string) error {
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
func (m *ModuleTransactionDummy) GetEnv(name string) string {
	return m.Env[name]
}

// GetEnvList returns a copy of the PAM environment as a map.
func (m *ModuleTransactionDummy) GetEnvList() (map[string]string, error) {
	if m.Env == nil {
		m.Env = make(map[string]string)
	}
	return m.Env, nil
}

// GetUser is similar to GetItem(User), but it would start a conversation if
// no user is currently set in PAM.
func (m *ModuleTransactionDummy) GetUser(prompt string) (string, error) {
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
func (m *ModuleTransactionDummy) SetData(key string, data any) error {
	if m.Data == nil {
		m.Data = make(map[string]any)
	}

	m.Data[key] = data
	return nil
}

// GetData allows to get any value from the module data saved using SetData
// that is preserved across the whole time the module is loaded.
func (m *ModuleTransactionDummy) GetData(key string) (any, error) {
	data, found := m.Data[key]
	if !found {
		return nil, pam.NoModuleData
	}
	return data, nil
}

// StartStringConv starts a text-based conversation using the provided style
// and prompt.
func (m *ModuleTransactionDummy) StartStringConv(style pam.Style, prompt string) (
	pam.StringConvResponse, error) {
	if style == pam.BinaryPrompt {
		return nil, pam.NewTransactionError(errors.New("Binary style is not supported"),
			pam.ConvErr)
	}

	res, err := m.StartConv(pam.NewStringConvRequest(style, prompt))
	if err != nil {
		return nil, err
	}

	stringRes, ok := res.(pam.StringConvResponse)
	if !ok {
		return nil, pam.NewTransactionError(errors.New("Can't convert to pam.StringConvResponse"), pam.ConvErr)
	}
	return stringRes, nil
}

// StartStringConvf allows to start string conversation with formatting support.
func (m *ModuleTransactionDummy) StartStringConvf(style pam.Style, format string, args ...interface{}) (
	pam.StringConvResponse, error) {
	return m.StartStringConv(style, fmt.Sprintf(format, args...))
}

// StartBinaryConv starts a binary conversation using the provided bytes.
func (m *ModuleTransactionDummy) StartBinaryConv(bytes []byte) (
	pam.BinaryConvResponse, error) {
	res, err := m.StartConv(pam.NewBinaryConvRequestFromBytes(bytes))
	if err != nil {
		return nil, err
	}

	binaryRes, ok := res.(pam.BinaryConvResponse)
	if !ok {
		return nil, pam.NewTransactionError(
			errors.New("Can't convert to pam.BinaryConvResponse"), pam.ConvErr)
	}
	return binaryRes, nil
}

// StartConv initiates a PAM conversation using the provided ConvRequest.
func (m *ModuleTransactionDummy) StartConv(req pam.ConvRequest) (
	pam.ConvResponse, error) {
	resp, err := m.StartConvMulti([]pam.ConvRequest{req})
	if err != nil {
		return nil, err
	}
	if len(resp) != 1 {
		return nil, pam.NewTransactionError(errors.New("not enough values returned"),
			pam.ConvErr)
	}
	return resp[0], nil
}

// StartConvMulti initiates a PAM conversation with multiple ConvRequest's.
func (m *ModuleTransactionDummy) StartConvMulti(requests []pam.ConvRequest) (
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
			goReplies = append(goReplies, StringResponseDummy{
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
				BinaryResponseDummy{pam.BinaryPointer(&reply)})
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

// StringResponseDummy is a simple implementation of pam.StringConvResponse.
type StringResponseDummy struct {
	style   pam.Style
	content string
}

// Style returns the conversation style of the DummyStringResponse.
func (s StringResponseDummy) Style() pam.Style {
	return s.style
}

// Response returns the string response of the DummyStringResponse.
func (s StringResponseDummy) Response() string {
	return s.content
}

// BinaryResponseDummy is an implementation of pam.BinaryConvResponse.
type BinaryResponseDummy struct {
	ptr pam.BinaryPointer
}

// Style returns the response style for the response, so always BinaryPrompt.
func (b BinaryResponseDummy) Style() pam.Style {
	return pam.BinaryPrompt
}

// Data returns the response native pointer, it's up to the protocol to parse
// it accordingly.
func (b BinaryResponseDummy) Data() pam.BinaryPointer {
	return b.ptr
}

// Decode decodes the binary data using the provided decoder function.
func (b BinaryResponseDummy) Decode(decoder pam.BinaryDecoder) (
	[]byte, error) {
	if decoder == nil {
		return nil, errors.New("nil decoder provided")
	}
	return decoder(b.ptr)
}
