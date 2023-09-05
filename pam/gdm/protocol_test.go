package gdm

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func reformatJSON(t *testing.T, input []byte) []byte {
	// We can't safely compare for JSON values when generated via protobuf
	// so we initially pass it to native implementation to make it rebuild
	// the JSON data so that the output is more reliable.
	// See: https://protobuf.dev/reference/go/faq/#unstable-json
	t.Helper()
	var js json.RawMessage
	err := json.Unmarshal(input, &js)
	require.NoError(t, err)
	out, err := json.Marshal(js)
	require.NoError(t, err)
	return out
}

func TestGdmStructsMarshal(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		gdmData *Data

		wantJSON   string
		wantErrMsg string
	}{
		"Hello packet": {
			gdmData: &Data{Type: DataType_hello},

			wantJSON: `{"type":"hello"}`,
		},

		"Hello packet with data": {
			gdmData: &Data{Type: DataType_hello, Hello: &HelloData{Version: 55}},

			wantJSON: `{"type":"hello","hello":{"version":55}}`,
		},

		"Event packet": {
			gdmData: &Data{
				Type: DataType_event,
				Event: &EventData{
					Type: EventType_brokerSelected,
					Data: &EventData_BrokerSelected{},
				},
			},

			wantJSON: `{"type":"event","event":{"type":"brokerSelected","brokerSelected":{}}}`,
		},

		"Event ack packet": {
			gdmData: &Data{Type: DataType_eventAck},

			wantJSON: `{"type":"eventAck"}`,
		},

		"Request packet": {
			gdmData: &Data{
				Type: DataType_request,
				Request: &RequestData{
					Type: RequestType_uiLayoutCapabilities,
					Data: &RequestData_UiLayoutCapabilities{},
				},
			},

			wantJSON: `{"type":"request","request":{"type":"uiLayoutCapabilities","uiLayoutCapabilities":{}}}`,
		},

		"Request packet with missing data": {
			gdmData: &Data{
				Type: DataType_request,
				Request: &RequestData{
					Type: RequestType_updateBrokersList,
				},
			},

			wantJSON: `{"type":"request","request":{"type":"updateBrokersList"}}`,
		},

		"Response packet": {
			gdmData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_uiLayoutCapabilities,
					Data: &ResponseData_UiLayoutCapabilities{},
				},
			},

			wantJSON: `{"type":"response","response":{"type":"uiLayoutCapabilities","uiLayoutCapabilities":{}}}`,
		},

		"Response packet with ack data": {
			gdmData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_changeStage,
					Data: &ResponseData_Ack{},
				},
			},

			wantJSON: `{"type":"response","response":{"type":"changeStage","ack":{}}}`,
		},

		"Poll packet": {
			gdmData: &Data{Type: DataType_poll},

			wantJSON: `{"type":"poll"}`,
		},

		"PollResponse packet": {
			gdmData: &Data{
				Type: DataType_pollResponse,
				PollResponse: []*EventData{
					{
						Type: EventType_brokerSelected,
						Data: &EventData_BrokerSelected{
							BrokerSelected: &Events_BrokerSelected{BrokerId: "a broker"},
						},
					},
				},
			},

			wantJSON: `{"type":"pollResponse","pollResponse":` +
				`[{"type":"brokerSelected","brokerSelected":{"brokerId":"a broker"}}]}`,
		},

		"PollResponse packet with multiple results": {
			gdmData: &Data{
				Type: DataType_pollResponse,
				PollResponse: []*EventData{
					{
						Type: EventType_brokerSelected,
						Data: &EventData_BrokerSelected{
							BrokerSelected: &Events_BrokerSelected{BrokerId: "a broker"},
						},
					},
					{
						Type: EventType_authModeSelected,
						Data: &EventData_AuthModeSelected{
							AuthModeSelected: &Events_AuthModeSelected{AuthModeId: "auth mode"},
						},
					},
				},
			},

			wantJSON: `{"type":"pollResponse","pollResponse":` +
				`[{"type":"brokerSelected","brokerSelected":{"brokerId":"a broker"}},` +
				`{"type":"authModeSelected","authModeSelected":{"authModeId":"auth mode"}}]}`,
		},

		"PollResponse packet with nil data": {
			gdmData: &Data{
				Type:         DataType_pollResponse,
				PollResponse: nil,
			},

			wantJSON: `{"type":"pollResponse"}`,
		},

		"PollResponse packet with empty data": {
			gdmData: &Data{
				Type:         DataType_pollResponse,
				PollResponse: []*EventData{},
			},

			wantJSON: `{"type":"pollResponse"}`,
		},

		// Error cases
		"Error empty packet": {
			gdmData: &Data{},

			wantErrMsg: "unexpected type unknownType",
		},

		"Error if packet has invalid type": {
			gdmData: &Data{Type: DataType(-1)},

			wantErrMsg: "unhandled type -1",
		},

		"Error hello packet with unexpected data": {
			gdmData: &Data{Type: DataType_hello, Request: &RequestData{}},

			wantErrMsg: "field Request should not be defined",
		},

		"Error event packet with unknown type": {
			gdmData: &Data{
				Type:  DataType_event,
				Event: &EventData{Type: EventType_unknownEvent},
			},

			wantErrMsg: "missing event type",
		},

		"Error event packet with invalid type": {
			gdmData: &Data{Type: DataType_event, Event: &EventData{Type: EventType(-1)}},

			wantErrMsg: "unexpected event type",
		},

		"Error event packet with missing data": {
			gdmData: &Data{Type: DataType_event, Event: nil},

			wantErrMsg: "missing event data",
		},

		"Error event packet with empty data": {
			gdmData: &Data{Type: DataType_event, Event: &EventData{}},

			wantErrMsg: "missing event type",
		},

		"Error event packet with missing type": {
			gdmData: &Data{Type: DataType_event, Event: &EventData{Data: &EventData_AuthModeSelected{}}},

			wantErrMsg: "missing event type",
		},

		"Error event packet with unexpected data": {
			gdmData: &Data{
				Type:  DataType_event,
				Event: &EventData{Type: EventType_authEvent, Data: &EventData_AuthModeSelected{}},
				Hello: &HelloData{},
			},

			wantErrMsg: "field Hello should not be defined",
		},

		"Error event ack packet with unexpected data": {
			gdmData: &Data{Type: DataType_eventAck, Event: &EventData{}},

			wantErrMsg: "field Event should not be defined",
		},

		"Error request packet with unknown type": {
			gdmData: &Data{Type: DataType_request, Request: &RequestData{Data: &RequestData_ChangeStage{}}},

			wantErrMsg: "missing request type",
		},

		"Error request packet with invalid type": {
			gdmData: &Data{Type: DataType_request, Request: &RequestData{Type: RequestType(-1)}},

			wantErrMsg: "unexpected request type",
		},

		"Error request packet with missing data": {
			gdmData: &Data{Type: DataType_request, Request: nil},

			wantErrMsg: "missing request data",
		},

		"Error request packet with empty data": {
			gdmData:    &Data{Type: DataType_request, Request: &RequestData{}},
			wantErrMsg: "missing request type",
		},

		"Error request packet with unexpected data": {
			gdmData: &Data{
				Type: DataType_request,
				Request: &RequestData{
					Type: RequestType_changeStage,
					Data: &RequestData_ChangeStage{},
				},
				Event: &EventData{},
			},

			wantErrMsg: "field Event should not be defined",
		},

		"Error response packet with missing data": {
			gdmData: &Data{Type: DataType_response},

			wantErrMsg: "missing response data",
		},

		"Error response packet with missing type": {
			gdmData: &Data{
				Type:     DataType_response,
				Response: &ResponseData{Data: &ResponseData_Ack{}},
			},

			wantErrMsg: "missing response type",
		},

		"Error response packet with invalid type": {
			gdmData: &Data{
				Type:     DataType_response,
				Response: &ResponseData{Type: RequestType(-1), Data: &ResponseData_Ack{}},
			},

			wantErrMsg: "unexpected request type -1",
		},

		"Error response packet with unexpected data": {
			gdmData: &Data{
				Type:     DataType_response,
				Response: &ResponseData{Type: RequestType_changeStage, Data: &ResponseData_Ack{}},
				Event:    &EventData{},
			},

			wantErrMsg: "field Event should not be defined",
		},

		"Error poll packet with unexpected data": {
			gdmData: &Data{Type: DataType_poll, Request: &RequestData{}},

			wantErrMsg: "field Request should not be defined",
		},

		"Error pollResponse packet with missing event type": {
			gdmData: &Data{
				Type: DataType_pollResponse,
				PollResponse: []*EventData{
					{
						Type: EventType_brokerSelected,
						Data: &EventData_BrokerSelected{
							BrokerSelected: &Events_BrokerSelected{BrokerId: "a broker"},
						},
					},
					{
						Data: &EventData_AuthModeSelected{
							AuthModeSelected: &Events_AuthModeSelected{AuthModeId: "auth mode"},
						},
					},
				},
			},

			wantErrMsg: "poll response data member 1 invalid: missing event type",
		},

		"Error pollResponse packet with event with missing type": {
			gdmData: &Data{
				Type: DataType_pollResponse,
				PollResponse: []*EventData{
					{},
					{
						Type: EventType_authModeSelected,
						Data: &EventData_AuthModeSelected{
							AuthModeSelected: &Events_AuthModeSelected{AuthModeId: "auth mode"},
						},
					},
				},
			},

			wantErrMsg: "poll response data member 0 invalid: missing event type",
		},

		"Error pollResponse packet with unexpected data": {
			gdmData: &Data{
				Type:         DataType_pollResponse,
				PollResponse: []*EventData{},
				Event:        &EventData{},
			},

			wantErrMsg: "field Event should not be defined",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			bytes, err := tc.gdmData.JSON()
			if tc.wantErrMsg != "" {
				require.ErrorContains(t, err, tc.wantErrMsg)
				return
			}
			require.NoError(t, err)

			formattedJSON := string(reformatJSON(t, bytes))
			require.Equal(t, tc.wantJSON, formattedJSON)

			// Now try to reconvert things back again
			gdmData, err := NewDataFromJSON(bytes)
			require.NoError(t, err)
			newBytes, err := gdmData.JSON()
			require.NoError(t, err)
			require.Equal(t, formattedJSON, string(reformatJSON(t, newBytes)))
		})
	}
}

func TestGdmStructsUnMarshal(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		JSON string

		wantData   *Data
		wantErrMsg string
	}{
		"hello packet": {
			JSON: `{"type":"hello"}`,

			wantData: &Data{Type: DataType_hello},
		},

		"Hello packet with data": {
			JSON: `{"type":"hello","hello":{"version":55}}`,

			wantData: &Data{Type: DataType_hello, Hello: &HelloData{Version: 55}},
		},

		"Event packet": {
			JSON: `{"type":"event","event":{"type":"brokerSelected","brokerSelected":{}}}`,

			wantData: &Data{
				Type: DataType_event,
				Event: &EventData{
					Type: EventType_brokerSelected,
					Data: &EventData_BrokerSelected{},
				},
			},
		},

		"Event ack packet": {
			JSON: `{"type":"eventAck"}`,

			wantData: &Data{Type: DataType_eventAck},
		},

		"Request packet": {
			JSON: `{"type":"request","request":{"type":"uiLayoutCapabilities","uiLayoutCapabilities":{}}}`,

			wantData: &Data{
				Type: DataType_request,
				Request: &RequestData{
					Type: RequestType_uiLayoutCapabilities,
					Data: &RequestData_UiLayoutCapabilities{},
				},
			},
		},

		"Request packet with missing data": {
			JSON: `{"type":"request","request":{"type":"updateBrokersList"}}`,

			wantData: &Data{
				Type: DataType_request,
				Request: &RequestData{
					Type: RequestType_updateBrokersList,
				},
			},
		},

		"Response packet": {
			JSON: `{"type":"response","response":{"type":"uiLayoutCapabilities","uiLayoutCapabilities":{}}}`,

			wantData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_uiLayoutCapabilities,
					Data: &ResponseData_UiLayoutCapabilities{},
				},
			},
		},

		"Response packet with ack data": {
			JSON: `{"type":"response","response":{"type":"changeStage","ack":{}}}`,

			wantData: &Data{
				Type: DataType_response,
				Response: &ResponseData{
					Type: RequestType_changeStage,
					Data: &ResponseData_Ack{},
				},
			},
		},

		"Poll packet": {
			JSON: `{"type":"poll"}`,

			wantData: &Data{Type: DataType_poll},
		},

		"PollResponse packet": {
			JSON: `{"type":"pollResponse","pollResponse":` +
				`[{"type":"brokerSelected","brokerSelected":{"brokerId":"a broker"}}]}`,

			wantData: &Data{
				Type: DataType_pollResponse,
				PollResponse: []*EventData{
					{
						Type: EventType_brokerSelected,
						Data: &EventData_BrokerSelected{
							BrokerSelected: &Events_BrokerSelected{BrokerId: "a broker"},
						},
					},
				},
			},
		},

		"PollResponse packet with missing data": {
			JSON: `{"type":"pollResponse"}`,

			wantData: &Data{
				Type:         DataType_pollResponse,
				PollResponse: nil,
			},
		},

		// Error cases
		"Error empty packet ": {
			wantErrMsg: "syntax error",
		},

		"Error empty packet object": {
			JSON: `{}`,

			wantErrMsg: "unexpected type unknownType",
		},

		"Error packet with invalid type": {
			JSON: `{"type":"invalidType"}`,

			wantErrMsg: "invalid value for enum type",
		},

		"Error packet with invalid value type": {
			JSON: `{"type":[]}`,

			wantErrMsg: "invalid value for enum type",
		},

		"Error hello packet with unexpected data": {
			JSON: `{"type":"hello","request":{}}`,

			wantErrMsg: "field Request should not be defined",
		},

		"Error event packet with invalid data": {
			JSON: `{"type":"event","fooEvent":null}`,

			wantErrMsg: `unknown field "fooEvent"`,
		},

		"Error event packet with missing type": {
			JSON:       `{"type":"event","event":{}}`,
			wantErrMsg: "missing event type",
		},

		"Error event packet with unknown type": {
			JSON: `{"type":"event","event":{"type":"someType"}`,

			wantErrMsg: "invalid value for enum type",
		},

		"Error event packet with invalid value type": {
			JSON: `{"type":"event","event":{"brokerSelected":{},"type":{}}}`,

			wantErrMsg: "invalid value for enum type",
		},

		"Error event packet with missing data": {
			JSON: `{"type":"event","event":{"type":"brokerSelected"}}`,

			wantErrMsg: "missing event data",
		},

		"Error event packet with unexpected data": {
			JSON: `{"type":"event","event":{"type":"brokerSelected",` +
				`"brokerSelected":{}},"request":{}}`,

			wantErrMsg: "field Request should not be defined",
		},

		"Error event ack packet with unexpected member": {
			JSON: `{"type":"eventAck","event":{}}`,

			wantErrMsg: "field Event should not be defined",
		},

		"Error request packet with missing type": {
			JSON: `{"type":"request","request":{"uiLayoutCapabilities":{}}}`,

			wantErrMsg: "missing request type",
		},

		"Error request packet with unknown type": {
			JSON: `{"type":"request","request":{"type":true,"uiLayoutCapabilities":{}}}`,

			wantErrMsg: "invalid value for enum type",
		},

		"Error request packet with unknown value type": {
			JSON: `{"type":"request","request":{"type":"someUnknownRequest",` +
				`"uiLayoutCapabilities":{}}}`,

			wantErrMsg: "invalid value for enum type",
		},

		"Error request packet with unexpected data": {
			JSON: `{"type":"request","request":{"type": "uiLayoutCapabilities",` +
				`"uiLayoutCapabilities":{}}, "event":{}}`,

			wantErrMsg: "field Event should not be defined",
		},

		"Error response packet with missing data": {
			JSON: `{"type":"response"}`,

			wantErrMsg: "missing response data",
		},

		"Error response packet with unexpected data": {
			JSON: `{"type":"response","response":{"type":"changeStage","ack":{}}, "event":{}}`,

			wantErrMsg: "field Event should not be defined",
		},

		"Error poll packet with unexpected data": {
			JSON: `{"type":"poll", "response": {}}`,

			wantErrMsg: "field Response should not be defined",
		},

		"Error pollResponse packet with missing event type": {
			JSON: `{"type":"pollResponse","pollResponse":` +
				`[{"type":"brokerSelected","brokerSelected":{"brokerId":"a broker"}},` +
				`{"authModeSelected":{"authModeId":"auth mode"}}]}`,

			wantErrMsg: "poll response data member 1 invalid: missing event type",
		},

		"Error pollResponse packet with unsupported event type": {
			JSON: `{"type":"pollResponse","pollResponse":` +
				`[{"type":"brokerSelected","brokerSelected":{"brokerId":"a broker"}},` +
				`{"type":"invalidEvent"}]}`,

			wantErrMsg: "invalid value for enum type",
		},

		"Error pollResponse packet with unexpected data": {
			JSON: `{"type":"pollResponse","pollResponse":` +
				`[{"type":"brokerSelected","brokerSelected":{"brokerId":"a broker"}},` +
				`{"type":"authModeSelected","authModeSelected":{"authModeId":"auth mode"}}],` +
				`"response":{}}`,

			wantErrMsg: "field Response should not be defined",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gdmData, err := NewDataFromJSON([]byte(tc.JSON))
			if tc.wantErrMsg != "" {
				require.ErrorContains(t, err, tc.wantErrMsg)
				return
			}
			require.NoError(t, err)

			bytes, err := tc.wantData.JSON()
			require.NoError(t, err)
			require.Equal(t, tc.JSON, string(reformatJSON(t, bytes)))

			// Convert back the data to JSON and check it's still matching.
			json, err := gdmData.JSON()
			require.NoError(t, err)
			require.Equal(t, tc.JSON, string(reformatJSON(t, json)))
		})
	}
}
