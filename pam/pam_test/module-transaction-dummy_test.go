package pam_test

import (
	"fmt"
	"testing"

	"github.com/msteinert/pam"
	"github.com/stretchr/testify/require"
)

func ptrValue[T any](value T) *T {
	return &value
}

func bytesPointerDecoder(ptr pam.BinaryPointer) ([]byte, error) {
	if ptr == nil {
		return nil, nil
	}
	return *(*[]byte)(ptr), nil
}

func TestSetGetItem(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		item  pam.Item
		value *string

		expectedValue    *string
		expectedGetError error
		expectedSetError error
	}{
		"set invalid item": {
			item:             pam.Item(-1),
			value:            ptrValue("some value"),
			expectedSetError: pam.BadItem,
		},

		"get invalid item": {
			item:             pam.Item(0),
			expectedGetError: pam.BadItem,
			expectedValue:    ptrValue(""),
		},

		"set user": {
			item:  pam.User,
			value: ptrValue("an user"),
		},

		"get unset user": {
			item:          pam.User,
			expectedValue: ptrValue(""),
		},

		"get and set user": {
			item:          pam.User,
			value:         ptrValue("the-user"),
			expectedValue: ptrValue("the-user"),
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// These test inputs can not be all unset
			if tc.value == nil && tc.expectedValue == nil {
				t.Fatalf("Setup: some test inputs were nil, but they must not be")
			}

			tx := NewModuleTransactionDummy(nil)

			if tc.value != nil {
				err := tx.SetItem(tc.item, *tc.value)
				require.ErrorIs(t, err, tc.expectedSetError)
			}

			if tc.expectedValue != nil {
				value, err := tx.GetItem(tc.item)
				require.Equal(t, value, *tc.expectedValue)
				require.ErrorIs(t, err, tc.expectedGetError)
			}
		})
	}
}

func TestSetPutEnv(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env          string
		value        *string
		presetValues map[string]string
		skipPut      bool

		expectedValue    *string
		expectedPutError error
	}{
		"put var": {
			env:   "AN_ENV",
			value: ptrValue("value"),
		},

		"unset non-preset var": {
			env:           "NEVER_SET_ENV",
			expectedValue: ptrValue(""),
		},

		"unset preset var": {
			presetValues:  map[string]string{"PRESET_ENV": "hey!"},
			env:           "PRESET_ENV",
			expectedValue: ptrValue(""),
		},

		"change preset var": {
			presetValues:  map[string]string{"PRESET_ENV": "hey!"},
			env:           "PRESET_ENV",
			value:         ptrValue("hello!"),
			expectedValue: ptrValue("hello!"),
		},

		"get unset env": {
			skipPut:       true,
			env:           "AN_UNSET_ENV",
			expectedValue: ptrValue(""),
		},

		"put invalid env": {
			env:              "",
			value:            ptrValue("Invalid Value"),
			expectedPutError: pam.BadItem,
		},

		"get invalid env": {
			env:           "",
			value:         ptrValue("Invalid Value"),
			expectedValue: ptrValue(""),
			skipPut:       true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// These test inputs can not be all unset
			if tc.skipPut && tc.expectedValue == nil {
				t.Fatalf("Setup: test case is missing data, no test will run")
			}

			tx := NewModuleTransactionDummy(nil)
			envList, err := tx.GetEnvList()
			require.NoErrorf(t, err, "Setup: GetEnvList should not return an error")
			require.Lenf(t, envList, 0, "Setup: GetEnvList should have elements")

			if tc.presetValues != nil && !tc.skipPut {
				for env, value := range tc.presetValues {
					err := tx.PutEnv(env + "=" + value)
					require.NoError(t, err)
				}
				envList, err = tx.GetEnvList()
				require.NoError(t, err)
				require.Equal(t, tc.presetValues, envList)
			}

			if !tc.skipPut {
				var env string
				if tc.value != nil {
					env = tc.env + "=" + *tc.value
				} else {
					env = tc.env
				}
				err := tx.PutEnv(env)
				require.ErrorIs(t, err, tc.expectedPutError)

				if tc.expectedPutError == nil {
					environment, err := tx.GetEnvList()
					require.NoError(t, err)

					if tc.value != nil && tc.expectedValue != nil {
						require.Equal(t, map[string]string{
							tc.env: *tc.expectedValue}, environment)
					} else if tc.value != nil {
						require.Equal(t, map[string]string{tc.env: *tc.value},
							environment)
					} else {
						require.Equal(t, map[string]string{}, environment)
					}
				} else {
					environment, err := tx.GetEnvList()
					require.NoError(t, err)
					require.Equal(t, map[string]string{}, environment)
				}
			}

			if tc.expectedValue != nil {
				value := tx.GetEnv(tc.env)
				require.Equal(t, value, *tc.expectedValue)
			}
		})
	}
}

func TestSetGetData(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		key        string
		data       any
		presetData map[string]any
		skipSet    bool
		skipGet    bool

		expectedData     any
		expectedSetError error
		expectedGetError error
	}{
		"get missing": {
			skipSet:          true,
			key:              "not set",
			expectedGetError: pam.NoModuleData,
		},

		"set-get data": {
			presetData:   map[string]any{"some-data": []any{"hey! That's", true}},
			key:          "data",
			data:         []any{"hey! That's", true},
			expectedData: []any{"hey! That's", true},
		},

		"set replaces data": {
			presetData: map[string]any{"some-data": []any{"hey! That's", true}},
			key:        "some-data",
			data: ModuleTransactionDummy{
				Items: map[pam.Item]string{pam.Tty: "yay"},
				Env:   map[string]string{"foo": "bar"},
			},
			expectedData: ModuleTransactionDummy{
				Items: map[pam.Item]string{pam.Tty: "yay"},
				Env:   map[string]string{"foo": "bar"},
			},
		},

		"set nil removes data": {
			presetData:       map[string]any{"some-data": []any{"hey! That's", true}},
			key:              "some-data",
			data:             nil,
			expectedGetError: pam.NoModuleData,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// These test inputs can not be all unset
			if tc.skipGet && tc.skipSet {
				t.Fatalf("Setup: test case is missing data, no test will run")
			}

			tx := NewModuleTransactionDummy(nil)

			if tc.presetData != nil && !tc.skipSet {
				for key, value := range tc.presetData {
					err := tx.SetData(key, value)
					require.NoError(t, err)
				}
			}

			if !tc.skipSet {
				err := tx.SetData(tc.key, tc.data)
				require.ErrorIs(t, err, tc.expectedSetError)
			}

			if !tc.skipGet {
				data, err := tx.GetData(tc.key)
				require.ErrorIs(t, err, tc.expectedGetError)
				require.Equal(t, tc.expectedData, data)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		presetUser  string
		convHandler pam.ConversationHandler

		expected      string
		expectedError error
	}{
		"not-preset missing conv": {
			expected:      "",
			expectedError: pam.ConvErr,
		},

		"preset missing conv": {
			presetUser: "an-user",
			expected:   "an-user",
		},

		"preset with conv": {
			presetUser: "an-user",
			expected:   "an-user",
			convHandler: pam.ConversationFunc(func(s pam.Style, msg string) (string, error) {
				return "another-user", pam.ConvErr
			}),
		},

		"not-preset via conv": {
			expected: "provided-user",
			convHandler: pam.ConversationFunc(
				func(s pam.Style, msg string) (string, error) {
					require.Equal(t, msg, "Who are you?")
					if msg != "Who are you?" {
						return "", pam.ConvErr
					}
					if s == pam.PromptEchoOn {
						return "provided-user", nil
					}
					return "", pam.ConvErr
				}),
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tx := NewModuleTransactionDummy(tc.convHandler)

			if tc.presetUser != "" {
				err := tx.SetItem(pam.User, tc.presetUser)
				require.NoError(t, err)
			}

			prompt := "Who are you?"
			user, err := tx.GetUser(prompt)
			require.ErrorIs(t, err, tc.expectedError)
			require.Equal(t, tc.expected, user)
		})
	}
}

func TestStartStringConv(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		prompt                string
		promptFormat          string
		promptFormatArgs      []interface{}
		convStyle             pam.Style
		convError             error
		convHandler           *pam.ConversationFunc
		convShouldNotBeCalled bool

		expected      string
		expectedError error
	}{
		"normal string": {
			prompt:    "This is an error!",
			convStyle: pam.ErrorMsg,
			expected:  "I'm handling it fine though",
		},

		"formatted string": {
			promptFormat:     "Sending some %s, right? %v",
			promptFormatArgs: []interface{}{"info", true},
			convStyle:        pam.TextInfo,
			expected:         "And returning some text back",
		},

		"failing conv func": {
			prompt:        "Tell me your secret!",
			convStyle:     pam.PromptEchoOff,
			convError:     pam.BufErr,
			expectedError: pam.BufErr,
		},

		"no conv set fails": {
			convHandler:   ptrValue(pam.ConversationFunc(nil)),
			expectedError: pam.ConvErr,
		},

		"failing conv func per invalid style": {
			prompt:                "Tell me your secret!",
			convStyle:             pam.BinaryPrompt,
			convError:             pam.ConvErr,
			expectedError:         pam.ConvErr,
			convShouldNotBeCalled: true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			convFunCalled := false
			tx := NewModuleTransactionDummy(func() pam.ConversationFunc {
				if tc.convHandler != nil {
					return *tc.convHandler
				}
				prompt := tc.prompt
				if tc.promptFormat != "" {
					prompt = fmt.Sprintf(tc.promptFormat, tc.promptFormatArgs...)
				}
				return pam.ConversationFunc(
					func(style pam.Style, msg string) (string, error) {
						convFunCalled = true
						require.Equal(t, prompt, msg)
						require.Equal(t, tc.convStyle, style)
						return tc.expected, tc.convError
					})
			}())

			var reply pam.StringConvResponse
			var err error

			if tc.promptFormat != "" {
				reply, err = tx.StartStringConvf(tc.convStyle, tc.promptFormat,
					tc.promptFormatArgs...)
			} else {
				reply, err = tx.StartStringConv(tc.convStyle, tc.prompt)
			}

			expectConFuncCalled := !tc.convShouldNotBeCalled && tc.convHandler == nil

			require.Equal(t, expectConFuncCalled, convFunCalled)
			require.ErrorIs(t, err, tc.expectedError)

			if tc.expectedError != nil {
				require.Zero(t, reply)
				return
			}

			require.NotNil(t, reply)
			require.Equal(t, tc.expected, reply.Response())
			require.Equal(t, tc.convStyle, reply.Style())
		})
	}
}

func TestStartBinaryConv(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		request     []byte
		convError   error
		convHandler *pam.BinaryConversationHandler

		expected      []byte
		expectedError error
	}{
		"simple": {
			request:  []byte{0x01, 0x02, 0x03},
			expected: []byte{0x00, 0x01, 0x02, 0x03, 0x4},
		},

		"with error": {
			request:       []byte{0x03, 0x02, 0x01},
			convError:     pam.BufErr,
			expectedError: pam.BufErr,
		},

		"no conv set fails": {
			convHandler:   ptrValue(pam.BinaryConversationHandler(nil)),
			expectedError: pam.ConvErr,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			convFunCalled := false
			var tx pam.ModuleTransaction
			if tc.convHandler != nil {
				tx = NewModuleTransactionDummy(*tc.convHandler)
			} else {
				tx = NewModuleTransactionDummy(func() pam.BinaryConversationFunc {
					return pam.BinaryConversationFunc(
						func(ptr pam.BinaryPointer) ([]byte, error) {
							convFunCalled = true
							require.NotNil(t, ptr)
							bytes := *(*[]byte)(ptr)
							require.Equal(t, tc.request, bytes)
							return tc.expected, tc.convError
						})
				}())
			}
			response, err := tx.StartBinaryConv(tc.request)
			require.ErrorIs(t, err, tc.expectedError)
			require.Equal(t, tc.convHandler == nil, convFunCalled)

			if tc.expectedError != nil {
				require.Nil(t, response)
				return
			}

			defer response.Release()
			require.NotNil(t, response)
			require.Equal(t, pam.BinaryPrompt, response.Style())
			require.NotNil(t, response.Data())
			bytes, err := response.Decode(bytesPointerDecoder)
			require.NoError(t, err)
			require.Equal(t, tc.expected, bytes)

			bytes, err = response.Decode(nil)
			require.ErrorContains(t, err, "nil decoder provided")
			require.Nil(t, bytes)
		})
	}
}

type multiConvHandler struct {
	t                *testing.T
	responses        []pam.ConvResponse
	expectedRequests []pam.ConvRequest
	timesCalled      int
}

func (c *multiConvHandler) next() (pam.ConvRequest, pam.ConvResponse) {
	i := c.timesCalled
	c.timesCalled++

	return c.expectedRequests[i], c.responses[i]
}

func (c *multiConvHandler) RespondPAM(style pam.Style, prompt string) (string, error) {
	expectedReq, response := c.next()
	require.Equal(c.t, expectedReq.Style(), style)
	stringReq, ok := expectedReq.(pam.StringConvRequest)
	require.True(c.t, ok)
	require.Equal(c.t, stringReq.Prompt(), prompt)
	stringRes, ok := response.(pam.StringConvResponse)
	require.True(c.t, ok)
	return stringRes.Response(), nil
}

func (c *multiConvHandler) RespondPAMBinary(ptr pam.BinaryPointer) ([]byte, error) {
	expectedReq, response := c.next()
	require.Equal(c.t, expectedReq.Style(), pam.BinaryPrompt)

	binReq, ok := expectedReq.(pam.BinaryConvRequester)
	require.True(c.t, ok)
	expectedReqBytes, err := bytesPointerDecoder(binReq.Pointer())
	require.NoError(c.t, err)
	actualReqBytes, err := bytesPointerDecoder(ptr)
	require.NoError(c.t, err)
	require.Equal(c.t, expectedReqBytes, actualReqBytes)

	bytes, err := response.(pam.BinaryConvResponse).Decode(bytesPointerDecoder)
	require.NoError(c.t, err)
	return bytes, nil
}

func TestStartConvMulti(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		requests []pam.ConvRequest

		expectedResponses []pam.ConvResponse
		expectedError     error
	}{
		"no requests": {
			expectedError: pam.ConvErr,
		},

		"string requests": {
			requests: []pam.ConvRequest{
				pam.NewStringConvRequest(pam.PromptEchoOff, "give some PromptEchoOff"),
				pam.NewStringConvRequest(pam.PromptEchoOn, "give some PromptEchoOn"),
				pam.NewStringConvRequest(pam.ErrorMsg, "give some ErrorMsg"),
				pam.NewStringConvRequest(pam.TextInfo, "give some TextInfo"),
			},
			expectedResponses: []pam.ConvResponse{
				StringResponseDummy{pam.PromptEchoOff, "answer to PromptEchoOff"},
				StringResponseDummy{pam.PromptEchoOn, "answer to PromptEchoOn"},
				StringResponseDummy{pam.ErrorMsg, "answer to ErrorMsg"},
				StringResponseDummy{pam.TextInfo, "answer to TextInfo"},
			},
		},

		"binary requests": {
			requests: []pam.ConvRequest{
				NewBinaryRequestDummy(nil),
				NewBinaryRequestDummy(pam.BinaryPointer(&[]byte{})),
				NewBinaryRequestDummy(pam.BinaryPointer(&[]byte{0xFF, 0x00, 0xBA, 0xAB})),
				NewBinaryRequestDummy(pam.BinaryPointer(&[]byte{0x55})),
			},
			expectedResponses: []pam.ConvResponse{
				&BinaryResponseDummy{pam.BinaryPointer(&[]byte{})},
				&BinaryResponseDummy{nil},
				&BinaryResponseDummy{pam.BinaryPointer(&[]byte{0x53})},
				&BinaryResponseDummy{pam.BinaryPointer(&[]byte{0xAF, 0x00, 0xBA, 0xAC})},
			},
		},

		"mixed requests": {
			requests: []pam.ConvRequest{
				NewBinaryRequestDummy(nil),
				pam.NewStringConvRequest(pam.PromptEchoOff, "PromptEchoOff"),
				NewBinaryRequestDummy(pam.BinaryPointer(&[]byte{})),
				pam.NewStringConvRequest(pam.PromptEchoOn, "PromptEchoOn"),
				NewBinaryRequestDummy(pam.BinaryPointer(&[]byte{0xFF, 0x00, 0xBA, 0xAB})),
				pam.NewStringConvRequest(pam.ErrorMsg, "ErrorMsg"),
				NewBinaryRequestDummy(pam.BinaryPointer(&[]byte{0x55})),
				pam.NewStringConvRequest(pam.TextInfo, "TextInfo"),
			},
			expectedResponses: []pam.ConvResponse{
				&BinaryResponseDummy{pam.BinaryPointer(&[]byte{})},
				StringResponseDummy{pam.PromptEchoOff, "PromptEchoOff"},
				&BinaryResponseDummy{pam.BinaryPointer(&[]byte{0x55})},
				StringResponseDummy{pam.PromptEchoOn, "PromptEchoOn"},
				&BinaryResponseDummy{nil},
				StringResponseDummy{pam.ErrorMsg, "ErrorMsg"},
				&BinaryResponseDummy{pam.BinaryPointer(&[]byte{0xAF, 0x00, 0xBA, 0xAC})},
				StringResponseDummy{pam.TextInfo, "TextInfo"},
			},
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equalf(t, len(tc.expectedResponses), len(tc.requests),
				"Setup: mismatch on expectations / requests numbers")

			convHandler := &multiConvHandler{
				t:                t,
				expectedRequests: tc.requests,
				responses:        tc.expectedResponses,
			}
			tx := NewModuleTransactionDummy(convHandler)

			responses, err := tx.StartConvMulti(tc.requests)
			require.ErrorIs(t, err, tc.expectedError)
			require.Equal(t, len(tc.requests), convHandler.timesCalled)

			if tc.expectedError != nil {
				require.Nil(t, responses)
				return
			}

			require.NotNil(t, responses)
			require.Len(t, responses, len(tc.requests))

			for i, res := range responses {
				expected := tc.expectedResponses[i]
				require.Equal(t, expected.Style(), res.Style())

				switch r := res.(type) {
				case pam.BinaryConvResponse:
					expBinRes, ok := expected.(pam.BinaryConvResponse)
					require.True(t, ok)
					eb, err := expBinRes.Decode(bytesPointerDecoder)
					require.NoError(t, err)
					bytes, err := r.Decode(bytesPointerDecoder)
					require.NoError(t, err)
					require.Equal(t, eb, bytes)
				default:
					require.Equal(t, expected, res)
				}
			}
		})
	}
}
