package gdm

import (
	"errors"
	"testing"

	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/pam_test"
)

func TestSendToGdm(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value []byte

		wantReturn []byte
		wantError  error
	}{
		"JSON null data can be sent and received": {
			value: []byte(`null`),
		},

		"JSON number can be sent and received": {
			value: []byte(`1.5`),
		},

		"Single char is sent and received as string": {
			value: []byte(`"m"`),
		},

		"JSON null is returned": {
			value:      []byte(`"give me 🚫"`),
			wantReturn: []byte("null"),
		},

		"Utf-8 data is sent and returned": {
			value:      []byte(`"give me 🍕"`),
			wantReturn: []byte(`"😋"`),
		},

		// Error cases
		"Error on empty data": {
			value:     []byte{},
			wantError: ErrInvalidJSON,
		},

		"Error on nil data": {
			value:     nil,
			wantError: ErrInvalidJSON,
		},

		"Error with empty data returned": {
			value:      []byte(`"give me 🗑‼"`),
			wantReturn: []byte{},
			wantError:  ErrInvalidJSON,
		},

		"Error with nil data returned": {
			value:      []byte(`"give me 🚫"`),
			wantReturn: []byte(nil),
			wantError:  ErrInvalidJSON,
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

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
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value *Data

		wantReturn []byte
		wantError  error
	}{
		"Null JSON value can be returned": {
			value: &Data{
				Type: DataType_event,
				Event: &EventData{
					Type: EventType_brokerSelected,
					Data: &EventData_BrokerSelected{},
				},
			},

			wantReturn: []byte("null"),
		},

		"Hello packet can be sent": {
			value: &Data{
				Type:  DataType_hello,
				Hello: &HelloData{Version: 12345},
			},
			wantReturn: []byte(`"hello gdm!"`),
		},

		// Error cases
		"Error with empty data": {
			value:      &Data{},
			wantReturn: nil,
			wantError:  errors.New("expected type unknownType"),
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
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			convFuncCalled := true
			mt := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
				func(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
					convFuncCalled = true
					require.NotNil(t, ptr)
					req, err := decodeJSONProtoMessage(ptr)
					require.NoError(t, err)
					valueJSON, err := tc.value.JSON()
					require.NoError(t, err)
					require.Equal(t, string(valueJSON), string(req))
					if tc.wantReturn != nil {
						msg, err := newJSONProtoMessage(tc.wantReturn)
						require.NoError(t, err)
						return pam.BinaryPointer(msg), tc.wantError
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
				return
			}

			require.Equal(t, tc.value, data)
		})
	}
}

func TestDataParsedSend(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	// To ensure we test all the code paths...
	log.SetLevel(log.DebugLevel)

	testCases := map[string]struct {
		value *Data

		// USE JSON for return data, so that we can also return invalid things
		wantReturn *Data
		wantError  error
	}{
		"Null value can be returned": {
			value: &Data{
				Type: DataType_event,
				Event: &EventData{
					Type: EventType_brokerSelected,
					Data: &EventData_BrokerSelected{},
				},
			},
			// FIXME: is it true?! that is ignored...
			wantReturn: nil,
		},

		// "Empty value can be returned": {
		// 	value: &Data{
		// 		Type: DataType_event,
		// 		Event: &EventData{
		// 			Type: EventType_brokerSelected,
		// 			Data: &EventData_BrokerSelected{},
		// 		},
		// 	},
		// 	wantData: &Data{},
		// },

		"Hello packet can be sent and received": {
			value: &Data{
				Type: DataType_hello,
			},
		},

		"Hello packet can be sent with response": {
			value: &Data{
				Type: DataType_hello,
			},
			wantReturn: &Data{
				Type:  DataType_hello,
				Hello: &HelloData{Version: 12345},
			},
		},

		// Error cases
		"Error with empty data": {
			value:     &Data{},
			wantError: errors.New("expected type unknownType"),
		},

		// "Error returning empty packet": {
		// 	value: &Data{
		// 		Type: DataType_hello,
		// 	},
		// 	wantReturn: &Data{},
		// 	wantError:  errors.New("expected type unknownType"),
		// },

		// "Error on missing data return": {
		// 	value: &Data{
		// 		Type: DataType_event,
		// 		Event: &EventData{
		// 			Type: EventType_brokerSelected,
		// 			Data: nil,
		// 		},
		// 	},

		// 	wantError: errors.New("missing event data"),
		// },

		// "Error on wrong data": {
		// 	value: &Data{
		// 		Type:    DataType_event,
		// 		Request: &RequestData{},
		// 	},
		// 	wantError: errors.New("missing event type"),
		// },
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			convFuncCalled := true
			// FIXME: factorize with the case above
			mt := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
				func(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
					convFuncCalled = true
					require.NotNil(t, ptr)
					req, err := decodeJSONProtoMessage(ptr)
					require.NoError(t, err)
					valueJSON, err := tc.value.JSON()
					require.NoError(t, err)
					req = reformatJSONIndented(t, req)
					valueJSON = reformatJSONIndented(t, valueJSON)
					require.Equal(t, string(valueJSON), string(req))
					if tc.wantReturn != nil {
						data, err := tc.wantReturn.JSON()
						require.NoError(t, err)
						msg, err := newJSONProtoMessage(data)
						require.NoError(t, err)
						return pam.BinaryPointer(msg), tc.wantError
					}
					msg, err := newJSONProtoMessage(req)
					require.NoError(t, err)
					return pam.BinaryPointer(msg), tc.wantError
				}))

			data, err := tc.value.SendParsed(mt)
			require.True(t, convFuncCalled)

			if tc.wantError != nil {
				require.Nil(t, data)
				require.Error(t, tc.wantError, err)
				return
			}

			require.NoError(t, err)

			if tc.wantReturn != nil {
				requireEqualData(t, tc.wantReturn, data)
				return
			}

			requireEqualData(t, tc.value, data)
		})
	}
}
