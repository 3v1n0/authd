package gdm

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func objectToRaw(t *testing.T, obj Object) RawObject {
	t.Helper()
	raw, err := obj.ToRawMessage()
	require.NoError(t, err)
	return raw
}

func valueToRawJSON[T any](t *testing.T, value T) json.RawMessage {
	t.Helper()
	bytes, err := json.Marshal(value)
	require.NoError(t, err)
	return bytes
}

func valuesToRawJSON(t *testing.T, values ...any) []json.RawMessage {
	t.Helper()
	rawValues := make([]json.RawMessage, len(values))
	for i, value := range values {
		rawValues[i] = valueToRawJSON(t, value)
	}
	return rawValues
}

func TestGdmStructsMarshal(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		gdmData            Data
		ignoreReconversion bool

		wantJSON  string
		wantError string
	}{
		"Hello packet": {
			gdmData:  Data{Type: Hello},
			wantJSON: `{"type":"hello"}`,
		},

		"Hello packet with data": {
			gdmData:  Data{Type: Hello, HelloData: &HelloData{Version: 55}},
			wantJSON: `{"type":"hello","helloData":{"version":55}}`,
		},

		"Event packet": {
			gdmData: Data{
				Type: Event, EventType: BrokerSelected,
				EventData: objectToRaw(t, Object{"name": "foo"}),
			},
			wantJSON: `{"type":"event","eventType":"brokerSelected",` +
				`"eventData":{"name":"foo"}}`,
		},

		"Event packet with capital name": {
			gdmData: Data{
				Type: Event, EventType: UILayoutReceived,
				EventData: objectToRaw(t, Object{"name": "bar"}),
			},
			wantJSON: `{"type":"event","eventType":"uiLayoutReceived",` +
				`"eventData":{"name":"bar"}}`,
		},

		"Event packet with unknown type": {
			gdmData:   Data{Type: Event, EventType: UnknownEvent},
			wantError: "missing event type",
		},

		"Event ack packet": {
			gdmData:  Data{Type: EventAck},
			wantJSON: `{"type":"eventAck"}`,
		},

		"Request packet": {
			gdmData: Data{
				Type: Request, RequestType: UILayoutCapabilities,
				RequestData: Object{"name": "foo"},
			},
			wantJSON: `{"type":"request","requestType":"uiLayoutCapabilities",` +
				`"requestData":{"name":"foo"}}`,
		},

		"Request packet with missing data": {
			gdmData:  Data{Type: Request, RequestType: UpdateBrokersList},
			wantJSON: `{"type":"request","requestType":"updateBrokersList"}`,
		},

		"Response packet": {
			gdmData: Data{
				Type:         Response,
				ResponseData: valuesToRawJSON(t, Object{"name": "foo"}, Object{"name": "bar"}),
			},
			wantJSON: `{"type":"response","responseData":[{"name":"foo"},{"name":"bar"}]}`,
		},

		"Response packet with empty data": {
			gdmData: Data{
				Type:         Response,
				ResponseData: []json.RawMessage{},
			},
			wantJSON:           `{"type":"response"}`,
			ignoreReconversion: true,
		},

		"Response packet with mixed data": {
			gdmData: Data{
				Type: Response,
				ResponseData: valuesToRawJSON(t,
					Object{"name": "foo"}, true, "string", 12345, 0.55),
			},
			wantJSON: `{"type":"response","responseData":[{"name":"foo"},true,"string",12345,0.55]}`,
		},

		"Poll packet": {
			gdmData:  Data{Type: Poll},
			wantJSON: `{"type":"poll"}`,
		},

		"PollResponse packet": {
			gdmData: Data{
				Type: PollResponse,
				PollResponseData: []Data{
					{
						Type:      Event,
						EventType: BrokerSelected,
						EventData: objectToRaw(t, Object{"foo": "bar"}),
					},
				},
			},
			wantJSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}}]}`,
		},

		"PollResponse packet with empty data": {
			gdmData: Data{
				Type:             PollResponse,
				PollResponseData: []Data{},
			},
			wantJSON:           `{"type":"pollResponse"}`,
			ignoreReconversion: true,
		},

		// Error cases
		"Error empty packet": {
			wantError: "unexpected type unknownType",
		},

		"Error if packet has invalid type": {
			gdmData:   Data{Type: lastDataType},
			wantError: "unhandled type unknownType",
		},

		"Error hello packet with unexpected data": {
			gdmData:   Data{Type: Hello, RequestData: Object{"foo": 1}},
			wantError: "field RequestData should not be defined",
		},

		"Error event packet with invalid type": {
			gdmData:   Data{Type: Event, EventType: lastEventType},
			wantError: "unexpected event type",
		},

		"Error event packet with missing data": {
			gdmData:   Data{Type: Event, EventType: UserSelected},
			wantError: "missing event data",
		},

		"Error event packet with unexpected data": {
			gdmData: Data{
				Type: Event, EventType: BrokerSelected,
				EventData:   objectToRaw(t, Object{"name": "foo"}),
				RequestData: Object{"foo": "bar"},
			},
			wantError: "field RequestData should not be defined",
		},

		"Error event ack packet with unexpected data": {
			gdmData:   Data{Type: EventAck, EventData: RawObject{}},
			wantError: "field EventData should not be defined",
		},

		"Error request packet with unknown type": {
			gdmData:   Data{Type: Request, RequestType: UnknownRequest},
			wantError: "missing request type",
		},

		"Error request packet with invalid type": {
			gdmData:   Data{Type: Request, RequestType: lastRequestType},
			wantError: "unexpected request type",
		},

		"Error request packet with unexpected data": {
			gdmData: Data{
				Type: Request, RequestType: UILayoutCapabilities,
				RequestData: Object{"name": "foo"},
				EventData:   objectToRaw(t, Object{"foo": "bar"}),
			},
			wantError: "field EventData should not be defined",
		},

		"Error response packet with missing data": {
			gdmData:   Data{Type: Response},
			wantError: "missing response data",
		},

		"Error response packet with unexpected data": {
			gdmData: Data{
				Type:         Response,
				ResponseData: valuesToRawJSON(t, []any{Object{"name": "foo"}}),
				EventData:    objectToRaw(t, Object{"foo": "bar"}),
			},
			wantError: "field EventData should not be defined",
		},

		"Error poll packet with unexpected data": {
			gdmData:   Data{Type: Poll, RequestData: Object{"foo": 1}},
			wantError: "field RequestData should not be defined",
		},

		"Error pollResponse packet with missing event type": {
			gdmData: Data{
				Type: PollResponse,
				PollResponseData: []Data{
					{
						Type:      Event,
						EventType: BrokerSelected,
						EventData: objectToRaw(t, Object{"foo": "bar"}),
					},
					{
						Type:      Event,
						EventData: objectToRaw(t, Object{"broken": "yes"}),
					},
				},
			},
			wantError: "poll response data member 1 invalid: missing event type",
		},

		"Error pollResponse packet with unsupported data type": {
			gdmData: Data{
				Type: PollResponse,
				PollResponseData: []Data{
					{
						Type:      Event,
						EventType: BrokerSelected,
						EventData: objectToRaw(t, Object{"foo": "bar"}),
					},
					{
						Type: Poll,
					},
				},
			},
			wantError: "poll response data member 1 unsupported type: poll",
		},

		"Error pollResponse packet with unexpected data": {
			gdmData: Data{
				Type:             PollResponse,
				PollResponseData: []Data{},
				EventData:        objectToRaw(t, Object{"foo": "bar"}),
			},
			wantError: "field EventData should not be defined",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			bytes, err := tc.gdmData.JSON()
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantJSON, string(bytes))

			if !tc.ignoreReconversion {
				gdmData, err := NewDataFromJSON(bytes)
				require.NoError(t, err)
				require.Equal(t, tc.gdmData, *gdmData)
			}
		})
	}
}

func TestGdmStructsUnMarshal(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		JSON               string
		ignoreReconversion bool

		wantData  Data
		wantError string
	}{
		"hello packet": {
			JSON:     `{"type":"hello"}`,
			wantData: Data{Type: Hello},
		},

		"Hello packet with data": {
			JSON:     `{"type":"hello","helloData":{"version":55}}`,
			wantData: Data{Type: Hello, HelloData: &HelloData{Version: 55}},
		},

		"Event packet": {
			JSON: `{"type":"event","eventType":"brokerSelected",` +
				`"eventData":{"name":"foo"}}`,
			wantData: Data{
				Type: Event, EventType: BrokerSelected,
				EventData: objectToRaw(t, Object{"name": "foo"}),
			},
		},

		"Event packet with capital name": {
			JSON: `{"type":"event","eventType":"uiLayoutReceived",` +
				`"eventData":{"name":"bar"}}`,
			wantData: Data{
				Type: Event, EventType: UILayoutReceived,
				EventData: objectToRaw(t, Object{"name": "bar"}),
			},
		},

		"Event ack packet": {
			JSON:     `{"type":"eventAck"}`,
			wantData: Data{Type: EventAck},
		},

		"Request packet": {
			JSON: `{"type":"request","requestType":"uiLayoutCapabilities",` +
				`"requestData":{"name":"foo"}}`,
			wantData: Data{
				Type: Request, RequestType: UILayoutCapabilities,
				RequestData: Object{"name": "foo"},
			},
		},

		"Request packet with missing data": {
			JSON:     `{"type":"request","requestType":"updateBrokersList"}`,
			wantData: Data{Type: Request, RequestType: UpdateBrokersList},
		},

		"Response packet": {
			JSON: `{"type":"response","responseData":[{"name":"foo"},{"name":"bar"}]}`,
			wantData: Data{
				Type:         Response,
				ResponseData: valuesToRawJSON(t, Object{"name": "foo"}, Object{"name": "bar"}),
			},
		},

		"Response packet with empty data": {
			JSON: `{"type":"response","responseData":[]}`,
			wantData: Data{
				Type:         Response,
				ResponseData: valuesToRawJSON(t),
			},
			ignoreReconversion: true,
		},

		"Response packet with mixed data": {
			JSON: `{"type":"response","responseData":[{"name":"foo"},true,"string",12345,0.55]}`,
			wantData: Data{
				Type: Response,
				ResponseData: valuesToRawJSON(t,
					Object{"name": "foo"}, true, "string", 12345, 0.55,
				),
			},
		},

		"Poll packet": {
			JSON:     `{"type":"poll"}`,
			wantData: Data{Type: Poll},
		},

		"PollResponse packet": {
			JSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}}]}`,
			wantData: Data{
				Type: PollResponse,
				PollResponseData: []Data{
					{
						Type:      Event,
						EventType: BrokerSelected,
						EventData: objectToRaw(t, Object{"foo": "bar"}),
					},
				},
			},
		},

		"PollResponse packet with empty data": {
			JSON: `{"type":"pollResponse"}`,
			wantData: Data{
				Type:             PollResponse,
				PollResponseData: nil,
			},
		},

		// Error cases
		"Error empty packet ": {
			wantError: "unexpected end of JSON input",
		},

		"Error empty packet object": {
			JSON:      `{}`,
			wantError: "unexpected type unknownType",
		},

		"Error packet with invalid type": {
			JSON:      `{"type":"invalidType"}`,
			wantError: "unexpected type unknownType",
		},

		"Error packet with invalid value type": {
			JSON: `{"type":[]}`,
			wantError: (&json.UnmarshalTypeError{
				Value:  "array",
				Struct: "Data",
				Field:  "type",
				Type:   reflect.TypeOf(""),
			}).Error(),
		},

		"Error hello packet with unexpected data": {
			JSON:      `{"type":"hello","requestType":"updateBrokersList"}`,
			wantError: "field RequestType should not be defined",
		},

		"Error event packet with missing type": {
			JSON:      `{"type":"event","eventData":{"name":"foo"}}`,
			wantError: "missing event type",
		},

		"Error event packet with unknown type": {
			JSON:      `{"type":"event","eventData":{"name":"foo"},"eventType":"someType"}`,
			wantError: "missing event type",
		},

		"Error event packet with invalid value type": {
			JSON: `{"type":"event","eventData":{"name":"foo"},"eventType":{}}`,
			wantError: (&json.UnmarshalTypeError{
				Value:  "object",
				Struct: "Data",
				Field:  "eventType",
				Type:   reflect.TypeOf(""),
			}).Error(),
		},

		"Error event packet with missing data": {
			JSON:      `{"type":"event","eventType":"brokerSelected"}`,
			wantError: "missing event data",
		},

		"Error event packet with unexpected data": {
			JSON: `{"type":"event","eventType":"brokerSelected",` +
				`"eventData":{"name":"foo"},"requestType":"updateBrokersList"}`,
			wantError: "field RequestType should not be defined",
		},

		"Error event ack packet with unexpected member": {
			JSON:      `{"type":"eventAck","eventData":{"name":"foo"}}`,
			wantError: "field EventData should not be defined",
		},

		"Error request packet with missing type": {
			JSON:      `{"type":"request","requestData":{"name":"foo"}}`,
			wantError: "missing request type",
		},

		"Error request packet with unknown type": {
			JSON: `{"type":"request","requestType":true,` +
				`"requestData":{"name":"foo"}}`,
			wantError: (&json.UnmarshalTypeError{
				Value:  "bool",
				Struct: "Data",
				Field:  "requestType",
				Type:   reflect.TypeOf(""),
			}).Error(),
		},

		"Error request packet with unknown value type": {
			JSON: `{"type":"request","requestType":"someUnknownRequest",` +
				`"requestData":{"name":"foo"}}`,
			wantError: "missing request type",
		},

		"Error request packet with unexpected data": {
			JSON: `{"type":"request","requestType":"uiLayoutCapabilities",` +
				`"requestData":{"name":"foo"}, "eventType":"brokerSelected"}`,
			wantError: "field EventType should not be defined",
		},

		"Error response packet with missing data": {
			JSON:      `{"type":"response"}`,
			wantError: "missing response data",
		},

		"Error response packet with unexpected data": {
			JSON:      `{"type":"response","responseData":[], "eventType":"brokerSelected"}`,
			wantError: "field EventType should not be defined",
		},

		"Error poll packet with unexpected data": {
			JSON:      `{"type":"poll", "responseData": []}`,
			wantError: "field ResponseData should not be defined",
		},

		"Error pollResponse packet with missing event type": {
			JSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}},` +
				`{"type":"event","eventData":{"foo":"bar"}}]}`,
			wantError: "poll response data member 1 invalid: missing event type",
		},

		"Error pollResponse packet with unsupported data type": {
			JSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}},` +
				`{"type":"poll"}]}`,
			wantError: "poll response data member 1 unsupported type: poll",
		},

		"Error pollResponse packet with unexpected data": {
			JSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}}],` +
				`"responseData": []}`,
			wantError: "field ResponseData should not be defined",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gdmData, err := NewDataFromJSON([]byte(tc.JSON))
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantData, *gdmData)

			if !tc.ignoreReconversion {
				json, err := gdmData.JSON()
				require.NoError(t, err)
				require.Equal(t, tc.JSON, string(json))
			}
		})
	}
}
