package gdm

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"testing"

	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"
	authd "github.com/ubuntu/authd"
	"github.com/ubuntu/authd/pam/pam_test"
	"github.com/ubuntu/authd/pam/utils"
)

func reformatJSONIndented(t *testing.T, input []byte) []byte {
	t.Helper()

	var indented bytes.Buffer
	err := json.Indent(&indented, input, "", "  ")
	require.NoError(t, err)
	return indented.Bytes()
}

func requireEqualData(t *testing.T, want *Data, actual *Data) {
	t.Helper()

	// We can't compare data values as their content may contain elements
	// that may vary that are needed by protobuf implementation.
	// So let's compare the data JSON representation instead since that's what
	// we care about anyways.
	wantJSON, err := want.JSON()
	require.NoError(t, err)
	actualJSON, err := actual.JSON()
	require.NoError(t, err)

	require.Equal(t, string(reformatJSONIndented(t, wantJSON)),
		string(reformatJSONIndented(t, actualJSON)))
}

func TestSendToGdm(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value []byte

		wantReturn                   []byte
		wantError                    error
		wantConvHandlerNotToBeCalled bool
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
			value:                        []byte{},
			wantError:                    ErrInvalidJSON,
			wantConvHandlerNotToBeCalled: true,
		},
		"Error on nil data": {
			value:                        nil,
			wantError:                    ErrInvalidJSON,
			wantConvHandlerNotToBeCalled: true,
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

			convFuncCalled := false
			mtx := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
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

			data, err := sendToGdm(mtx, tc.value)
			require.Equal(t, convFuncCalled, !tc.wantConvHandlerNotToBeCalled)

			if tc.wantError != nil {
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

func TestDataSend(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value *Data

		wantReturn []byte
		wantError  error
	}{
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

		// Error cases
		"Error on empty data": {
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
			t.Cleanup(utils.MaybeDoLeakCheck)

			convFuncCalled := true
			mtx := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
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
						return pam.BinaryPointer(msg), nil
					}
					msg, err := newJSONProtoMessage(req)
					require.NoError(t, err)
					return pam.BinaryPointer(msg), tc.wantError
				}))

			data, err := tc.value.Send(mtx)
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

func TestDataSendParsed(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value *Data

		wantReturn *Data
		wantError  error
	}{
		"version data": {
			value: &Data{
				Type:  DataType_hello,
				Hello: &HelloData{Version: 12345},
			},
			wantReturn: &Data{Type: DataType_hello},
		},

		"event ack": {
			value: &Data{
				Type: DataType_event,
				Event: &EventData{
					Type: EventType_brokerSelected,
					Data: &EventData_BrokerSelected{},
				},
			},

			wantReturn: &Data{Type: DataType_eventAck},
		},

		// Error cases
		"Error on empty data": {
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
			t.Cleanup(utils.MaybeDoLeakCheck)

			convFuncCalled := true
			mtx := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
				func(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
					convFuncCalled = true
					require.NotNil(t, ptr)
					req, err := decodeJSONProtoMessage(ptr)
					require.NoError(t, err)
					valueJSON, err := tc.value.JSON()
					require.NoError(t, err)
					require.Equal(t, valueJSON, req)
					if tc.wantReturn != nil {
						bytes, err := tc.wantReturn.JSON()
						require.NoError(t, err)
						msg, err := newJSONProtoMessage(bytes)
						require.NoError(t, err)
						return pam.BinaryPointer(msg), nil
					}
					msg, err := newJSONProtoMessage(req)
					require.NoError(t, err)
					return pam.BinaryPointer(msg), tc.wantError
				}))

			data, err := tc.value.SendParsed(mtx)
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

func TestDataSendPoll(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		wantReturn *Data
		wantError  error
	}{
		"empty return": {
			wantReturn: &Data{
				Type: DataType_pollResponse,
			},
		},

		"return values": {
			wantReturn: &Data{
				Type: DataType_pollResponse,
				PollResponse: []*EventData{
					{Type: EventType_authEvent, Data: &EventData_AuthEvent{}},
					{Type: EventType_authModeSelected, Data: &EventData_AuthModeSelected{}},
					{Type: EventType_uiLayoutReceived, Data: &EventData_UiLayoutReceived{}},
				},
			},
		},

		"Error on nil return": {
			wantReturn: nil,
			wantError:  errors.New("unexpected token null"),
		},

		"Error on unexpected type": {
			wantReturn: &Data{Type: DataType_hello},
			wantError:  errors.New("gdm replied with an unexpected type: hello"),
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(utils.MaybeDoLeakCheck)

			convFuncCalled := true
			mtx := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
				func(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
					convFuncCalled = true
					require.NotNil(t, ptr)
					if tc.wantReturn != nil {
						bytes, err := tc.wantReturn.JSON()
						require.NoError(t, err)
						msg, err := newJSONProtoMessage(bytes)
						require.NoError(t, err)
						return pam.BinaryPointer(msg), nil
					}
					msg, err := newJSONProtoMessage([]byte("null"))
					require.NoError(t, err)
					return pam.BinaryPointer(msg), tc.wantError
				}))

			eventData, err := SendPoll(mtx)
			require.True(t, convFuncCalled)

			if tc.wantError != nil {
				require.Nil(t, eventData)
				require.Error(t, tc.wantError, err)
				return
			}

			require.NoError(t, err)
			requireEqualData(t, tc.wantReturn,
				&Data{Type: DataType_pollResponse, PollResponse: eventData})
		})
	}
}

type invalidRequest struct {
}

// This is to implement Request interface defined by protobuf.
//
//nolint:revive
func (*invalidRequest) isRequestData_Data() {}

type sendRequestTypedCase struct {
	request   Request
	wantData  *Data
	wantError error
}

func testDataSendRequestTyped[ResponseType Response](t *testing.T, specificCases map[string]sendRequestTypedCase) {
	t.Helper()

	testCases := map[string]sendRequestTypedCase{
		"Error with unknown request": {
			request:   &invalidRequest{},
			wantError: errors.New("no known request type"),
		},

		"Error with mismatching response type": {
			request: &RequestData_ChangeStage{},
			wantData: &Data{
				Type:     DataType_response,
				Response: &ResponseData{Type: RequestType_uiLayoutCapabilities},
			},
			wantError: errors.New("gdm replied with invalid response type"),
		},

		"Error with non-response type": {
			request: &RequestData_ChangeStage{},
			wantData: &Data{
				Type: DataType_hello,
			},
			wantError: errors.New("gdm replied with an unexpected type: hello"),
		},
	}
	maps.Copy(testCases, specificCases)

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(utils.MaybeDoLeakCheck)

			convFuncCalled := true
			mtx := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
				func(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
					convFuncCalled = true
					require.NotNil(t, ptr)
					if tc.wantData != nil {
						bytes, err := tc.wantData.JSON()
						require.NoError(t, err)
						msg, err := newJSONProtoMessage(bytes)
						require.NoError(t, err)
						return pam.BinaryPointer(msg), nil
					}
					msg, err := newJSONProtoMessage([]byte("null"))
					require.NoError(t, err)
					return pam.BinaryPointer(msg), tc.wantError
				}))

			response, err := SendRequestTyped[ResponseType](mtx, tc.request)
			require.True(t, convFuncCalled)

			if tc.wantError != nil {
				require.Nil(t, response)
				require.Error(t, tc.wantError, err)
				return
			}

			require.NoError(t, err)
			requireEqualData(t, tc.wantData, &Data{
				Type:     DataType_response,
				Response: &ResponseData{Type: tc.wantData.Response.Type, Data: response},
			})
		})
	}
}

func TestDataSendRequestTyped(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testDataSendRequestTyped[Response](t, map[string]sendRequestTypedCase{
		"Request with change state": {
			request: &RequestData_ChangeStage{},
			wantData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_changeStage,
					Data: &ResponseData_Ack{},
				},
			},
		},
		"Request with Ui layout capabilities": {
			request: &RequestData_UiLayoutCapabilities{},
			wantData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_uiLayoutCapabilities,
					Data: &ResponseData_UiLayoutCapabilities{},
				},
			},
		},
	})

	testDataSendRequestTyped[*ResponseData_Ack](t, map[string]sendRequestTypedCase{
		"Request with change state": {
			request: &RequestData_ChangeStage{},
			wantData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_changeStage,
					Data: &ResponseData_Ack{},
				},
			},
		},
		"Request with Ui layout capabilities": {
			request: &RequestData_UiLayoutCapabilities{},
			wantData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_uiLayoutCapabilities,
					Data: &ResponseData_UiLayoutCapabilities{},
				},
			},
			wantError: errors.New("impossible to convert"),
		},
	})

	testDataSendRequestTyped[*ResponseData_UiLayoutCapabilities](t, map[string]sendRequestTypedCase{
		"Request with change state": {
			request: &RequestData_ChangeStage{},
			wantData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_changeStage,
					Data: &ResponseData_Ack{},
				},
			},
			wantError: errors.New("impossible to convert"),
		},
		"Request with Ui layout capabilities": {
			request: &RequestData_UiLayoutCapabilities{},
			wantData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_uiLayoutCapabilities,
					Data: &ResponseData_UiLayoutCapabilities{
						UiLayoutCapabilities: &Responses_UiLayoutCapabilities{
							SupportedUiLayouts: []*authd.UILayout{
								{
									Type: "form",
								},
							},
						},
					},
				},
			},
		},
	})
}

type invalidEvent struct {
}

// This is to implement Request interface defined by protobuf.
//
//nolint:revive
func (*invalidEvent) isEventData_Data() {}

func TestDataEmitEvent(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		event        Event
		returnedData []byte

		wantEventType EventType
		wantError     error
	}{
		"Emit BrokersReceived": {
			event:         &EventData_BrokersReceived{},
			wantEventType: EventType_brokersReceived,
		},

		"Emit BrokerSelected": {
			event:         &EventData_BrokerSelected{},
			wantEventType: EventType_brokerSelected,
		},

		"Emit AuthModesReceived": {
			event:         &EventData_AuthModesReceived{},
			wantEventType: EventType_authModesReceived,
		},

		"Emit AuthModeSelected": {
			event:         &EventData_AuthModeSelected{},
			wantEventType: EventType_authModeSelected,
		},

		"Emit IsAuthenticatedRequested": {
			event:         &EventData_IsAuthenticatedRequested{},
			wantEventType: EventType_isAuthenticatedRequested,
		},

		"Emit StageChanged": {
			event:         &EventData_StageChanged{},
			wantEventType: EventType_stageChanged,
		},

		"Emit UiLayoutReceived": {
			event:         &EventData_UiLayoutReceived{},
			wantEventType: EventType_uiLayoutReceived,
		},

		"Emit AuthEvent": {
			event:         &EventData_AuthEvent{},
			wantEventType: EventType_authEvent,
		},

		"Emit ReselectAuthMode": {
			event:         &EventData_ReselectAuthMode{},
			wantEventType: EventType_reselectAuthMode,
		},

		"Error on nil event": {
			wantError: errors.New("no known event type"),
		},

		"Error on unexpected event type": {
			event:     &invalidEvent{},
			wantError: errors.New("no known event type"),
		},

		"Error on invalid data": {
			event:        &EventData_ReselectAuthMode{},
			returnedData: []byte("null"),
			wantError:    errors.New("unexpected token null"),
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(utils.MaybeDoLeakCheck)

			convFuncCalled := true
			mtx := pam_test.NewModuleTransactionDummy(pam.BinaryPointerConversationFunc(
				func(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
					convFuncCalled = true
					require.NotNil(t, ptr)
					if tc.returnedData != nil {
						msg, err := newJSONProtoMessage(tc.returnedData)
						require.NoError(t, err)
						return pam.BinaryPointer(msg), nil
					}

					jsonReq, err := decodeJSONProtoMessage(ptr)
					require.NoError(t, err)
					data, err := NewDataFromJSON(jsonReq)
					require.NoError(t, err)
					require.Equal(t, data.Type, DataType_event)
					require.Equal(t, data.Event.Type, tc.wantEventType)
					json, err := (&Data{Type: DataType_eventAck}).JSON()
					require.NoError(t, err)
					msg, err := newJSONProtoMessage(json)
					require.NoError(t, err)
					return pam.BinaryPointer(msg), tc.wantError
				}))

			err := EmitEvent(mtx, tc.event)
			require.True(t, convFuncCalled)

			if tc.wantError != nil {
				require.Error(t, tc.wantError, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
