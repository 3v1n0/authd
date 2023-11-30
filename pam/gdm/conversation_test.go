package gdm

import (
	"errors"
	"testing"

	"github.com/msteinert/pam"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/pam/pam_test"
	"github.com/ubuntu/authd/pam/utils"
)

func TestSendToGdm(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value []byte

		wantReturn []byte
		wantError  error
	}{
		"single-char": {
			value: []byte(`"m"`),
		},

		// "lorem ipsum string data": {
		// 	value: []byte(`
		//     Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
		// 	tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
		// 	quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
		// 	consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
		// 	cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat
		// 	non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
		// `),
		// },

		"JSON null data in-out": {
			value: []byte(`null`),
		},

		"JSON null data returned": {
			value:      []byte(`"give me 🚫"`),
			wantReturn: []byte("null"),
		},

		// "single-char returned": {
		// 	value:      []byte("give me 🍕"),
		// 	wantReturn: []byte{0xAF},
		// },

		// "lorem ipsum string data returned": {
		// 	value: []byte("give me 💬"),
		// 	wantReturn: []byte(`
		//     Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
		// 	tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
		// 	quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
		// 	consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
		// 	cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat
		// 	non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
		// `),
		// },

		"empty data": {
			value:     []byte{},
			wantError: ErrInvalidJSON,
		},

		"nil data": {
			value:     nil,
			wantError: ErrInvalidJSON,
		},

		"empty data returned": {
			value:      []byte(`"give me 🗑‼"`),
			wantReturn: []byte{},
			wantError:  ErrInvalidJSON,
		},

		"nil data returned": {
			value:      []byte(`"give me 🚫"`),
			wantReturn: []byte(nil),
			wantError:  ErrInvalidJSON,
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(utils.MaybeDoLeakCheck)

			convFuncCalled := true
			mt := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
				func(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
					convFuncCalled = true
					require.NotNil(t, ptr)
					req, err := decodeJSONProtoMessage(ptr)
					require.NoError(t, err)
					require.Equal(t, tc.value, req)
					if tc.wantReturn != nil {
						msg, err := newJSONProtoMessage(tc.wantReturn)
						return pam.BinaryPointer(msg), err
					}
					msg, err := newJSONProtoMessage(req)
					return pam.BinaryPointer(msg), err
				}))

			data, err := sendToGdm(mt, tc.value)
			require.True(t, convFuncCalled)

			if tc.wantError != nil {
				require.Error(t, tc.wantError, err)
				return
			}

			require.NoError(t, err)

			if tc.wantReturn != nil {
				require.Equal(t, tc.wantReturn, data)
			} else {
				require.Equal(t, tc.value, data)
			}
		})
	}
}

func TestDataSend(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value *Data

		wantReturn []byte
		wantError  error
	}{
		"empty data": {
			value:      &Data{},
			wantReturn: nil,
			wantError:  errors.New("expected type unknownType"),
		},

		"nil return": {
			value: &Data{
				Type: DataType_event,
				Event: &EventData{
					Type: EventType_brokerSelected,
					Data: &EventData_BrokerSelected{},
				},
			},

			wantReturn: []byte("null"),
		},

		"version data": {
			value: &Data{
				Type:  DataType_hello,
				Hello: &HelloData{Version: 12345},
			},
			wantReturn: []byte(`"hello gdm!"`),
		},

		"Error on missing data return": {
			value: &Data{
				Type: DataType_event,
				Event: &EventData{
					Type: EventType_brokerSelected,
					Data: nil,
				},
			},

			wantError: errors.New("missing event data"),
		},

		"Error on wrong data": {
			value: &Data{
				Type:    DataType_event,
				Request: &RequestData{},
			},
			wantError: errors.New("missing event type"),
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(utils.MaybeDoLeakCheck)

			convFuncCalled := true
			mt := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
				func(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
					convFuncCalled = true
					require.NotNil(t, ptr)
					req, err := decodeJSONProtoMessage(ptr)
					require.NoError(t, err)
					valueJSON, err := tc.value.JSON()
					require.NoError(t, err)
					require.Equal(t, valueJSON, req)
					if tc.wantReturn != nil {
						msg, err := newJSONProtoMessage(tc.wantReturn)
						require.NoError(t, err)
						return pam.BinaryPointer(msg),
							tc.wantError
					}
					msg, err := newJSONProtoMessage(req)
					require.NoError(t, err)
					return pam.BinaryPointer(msg), tc.wantError
				}))

			data, err := tc.value.Send(mt)
			require.True(t, convFuncCalled)

			if tc.wantError != nil {
				require.Nil(t, data)
				require.Error(t, tc.wantError, err)
				return
			}

			require.NoError(t, err)

			if tc.wantReturn != nil {
				require.Equal(t, tc.wantReturn, data)
			} else {
				require.Equal(t, tc.value, data)
			}
		})
	}
}
