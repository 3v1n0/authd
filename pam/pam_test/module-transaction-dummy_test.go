package pam_test

import (
	"fmt"
	"testing"

	"github.com/msteinert/pam"
	"github.com/stretchr/testify/require"
)

func ptrValue[T any](value T) *T {
	v := value
	return &v
}

func TestSetGetItem(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		item             pam.Item
		value            *string
		expectedGetError error
		expectedSetError error
		expectedValue    *string
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

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.True(t, tc.value != nil || tc.expectedValue != nil)

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

	testCases := map[string]struct {
		env              string
		value            *string
		presetValues     map[string]string
		skipPut          bool
		expectedPutError error
		expectedValue    *string
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

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.False(t, tc.skipPut && tc.expectedValue == nil)

			tx := NewModuleTransactionDummy(nil)
			envList, err := tx.GetEnvList()
			require.NoError(t, err)
			require.Len(t, envList, 0)

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

	testCases := map[string]struct {
		key              string
		data             any
		presetData       map[string]any
		expectedSetError error
		expectedGetError error
		expectedData     any
		skipSet          bool
		skipGet          bool
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

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.False(t, tc.skipGet && tc.skipSet)

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

	testCases := map[string]struct {
		presetUser    string
		convHandler   pam.ConversationHandler
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

	for name, tc := range testCases {
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

	testCases := map[string]struct {
		prompt                string
		promptFormat          string
		promptFormatArgs      []interface{}
		convStyle             pam.Style
		convError             error
		convHandler           *pam.ConversationFunc
		convShouldNotBeCalled bool
		expected              string
		expectedError         error
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

	for name, tc := range testCases {
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

			require.ErrorIs(t, err, tc.expectedError)
			expectConFuncCalled := !tc.convShouldNotBeCalled && tc.convHandler == nil
			require.Equal(t, expectConFuncCalled, convFunCalled)

			if tc.expectedError == nil {
				require.NotNil(t, reply)
				require.Equal(t, tc.expected, reply.Response())
				require.Equal(t, tc.convStyle, reply.Style())
			} else {
				require.Zero(t, reply)
			}
		})
	}
}

func TestStartBinaryConv(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		request       []byte
		convError     error
		convHandler   *pam.BinaryConversationHandler
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

	for name, tc := range testCases {
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
							bytes := getBinaryFromPointer(ptr, len(tc.request))
							require.Equal(t, tc.request, bytes)
							return tc.expected, tc.convError
						})
				}())
			}
			response, err := tx.StartBinaryConv(tc.request)
			require.ErrorIs(t, err, tc.expectedError)
			require.Equal(t, tc.convHandler == nil, convFunCalled)

			if tc.expectedError == nil {
				defer response.Release()
				require.NotNil(t, response)
				require.Equal(t, pam.BinaryPrompt, response.Style())
				require.NotNil(t, response.Data())
				bytes, err := response.Decode(func(ptr pam.BinaryPointer) ([]byte, error) {
					return *(*[]byte)(ptr), nil
				})
				require.NoError(t, err)
				require.Equal(t, tc.expected, bytes)

				bytes, err = response.Decode(nil)
				require.ErrorContains(t, err, "nil decoder provided")
				require.Nil(t, bytes)
			} else {
				require.Nil(t, response)
			}
		})
	}
}
