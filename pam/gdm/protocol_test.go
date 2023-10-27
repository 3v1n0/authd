package gdm

import (
	"encoding/json"
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

		expectedJSON  string
		expectedError string
	}{
		"empty": {
			expectedError: "unexpected type unknownType",
		},

		"invalid type": {
			gdmData:       Data{Type: lastDataType},
			expectedError: "unhandled type unknownType",
		},

		"hello": {
			gdmData:      Data{Type: Hello},
			expectedJSON: `{"type":"hello"}`,
		},

		"hello with data": {
			gdmData:      Data{Type: Hello, HelloData: &HelloData{Version: 55}},
			expectedJSON: `{"type":"hello","helloData":{"version":55}}`,
		},

		"hello with unexpected data": {
			gdmData:       Data{Type: Hello, RequestData: Object{"foo": 1}},
			expectedError: "field RequestData should not be defined",
		},

		"event": {
			gdmData: Data{
				Type: Event, EventType: BrokerSelected,
				EventData: objectToRaw(t, Object{"name": "foo"}),
			},
			expectedJSON: `{"type":"event","eventType":"brokerSelected",` +
				`"eventData":{"name":"foo"}}`,
		},

		"event with capital name": {
			gdmData: Data{
				Type: Event, EventType: UILayoutReceived,
				EventData: objectToRaw(t, Object{"name": "bar"}),
			},
			expectedJSON: `{"type":"event","eventType":"uiLayoutReceived",` +
				`"eventData":{"name":"bar"}}`,
		},

		"event with unknown type": {
			gdmData:       Data{Type: Event, EventType: UnknownEvent},
			expectedError: "missing event type",
		},

		"event with invalid type": {
			gdmData:       Data{Type: Event, EventType: lastEventType},
			expectedError: "unexpected event type",
		},

		"event with missing data": {
			gdmData:       Data{Type: Event, EventType: UserSelected},
			expectedError: "missing event data",
		},

		"event with unexpected data": {
			gdmData: Data{
				Type: Event, EventType: BrokerSelected,
				EventData:   objectToRaw(t, Object{"name": "foo"}),
				RequestData: Object{"foo": "bar"},
			},
			expectedError: "field RequestData should not be defined",
		},

		"event ack": {
			gdmData:      Data{Type: EventAck},
			expectedJSON: `{"type":"eventAck"}`,
		},

		"event ack with unexpected data": {
			gdmData:       Data{Type: EventAck, EventData: RawObject{}},
			expectedError: "field EventData should not be defined",
		},

		"request": {
			gdmData: Data{
				Type: Request, RequestType: UILayoutCapabilities,
				RequestData: Object{"name": "foo"},
			},
			expectedJSON: `{"type":"request","requestType":"uiLayoutCapabilities",` +
				`"requestData":{"name":"foo"}}`,
		},

		"request with unknown type": {
			gdmData:       Data{Type: Request, RequestType: UnknownRequest},
			expectedError: "missing request type",
		},

		"request with invalid type": {
			gdmData:       Data{Type: Request, RequestType: lastRequestType},
			expectedError: "unexpected request type",
		},

		"request with missing data": {
			gdmData:      Data{Type: Request, RequestType: UpdateBrokersList},
			expectedJSON: `{"type":"request","requestType":"updateBrokersList"}`,
		},

		"request with unexpected data": {
			gdmData: Data{
				Type: Request, RequestType: UILayoutCapabilities,
				RequestData: Object{"name": "foo"},
				EventData:   objectToRaw(t, Object{"foo": "bar"}),
			},
			expectedError: "field EventData should not be defined",
		},

		"response": {
			gdmData: Data{
				Type:         Response,
				ResponseData: valuesToRawJSON(t, Object{"name": "foo"}, Object{"name": "bar"}),
			},
			expectedJSON: `{"type":"response","responseData":[{"name":"foo"},{"name":"bar"}]}`,
		},

		"response with empty data": {
			gdmData: Data{
				Type:         Response,
				ResponseData: []json.RawMessage{},
			},
			expectedJSON:       `{"type":"response"}`,
			ignoreReconversion: true,
		},

		"response with mixed data": {
			gdmData: Data{
				Type: Response,
				ResponseData: valuesToRawJSON(t,
					Object{"name": "foo"}, true, "string", 12345, 0.55),
			},
			expectedJSON: `{"type":"response","responseData":[{"name":"foo"},true,"string",12345,0.55]}`,
		},

		"response with missing data": {
			gdmData:       Data{Type: Response},
			expectedError: "missing response data",
		},

		"response with unexpected data": {
			gdmData: Data{
				Type:         Response,
				ResponseData: valuesToRawJSON(t, Object{"name": "foo"}),
				EventData:    objectToRaw(t, Object{"foo": "bar"}),
			},
			expectedError: "field EventData should not be defined",
		},

		"poll": {
			gdmData:      Data{Type: Poll},
			expectedJSON: `{"type":"poll"}`,
		},

		"poll with unexpected data": {
			gdmData:       Data{Type: Poll, RequestData: Object{"foo": 1}},
			expectedError: "field RequestData should not be defined",
		},

		"pollResponse": {
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
			expectedJSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}}]}`,
		},

		"pollResponse with empty data": {
			gdmData: Data{
				Type:             PollResponse,
				PollResponseData: []Data{},
			},
			expectedJSON:       `{"type":"pollResponse"}`,
			ignoreReconversion: true,
		},

		"pollResponse with missing event type": {
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
			expectedError: "poll response data member 1 invalid: missing event type",
		},

		"pollResponse with unsupported data type": {
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
			expectedError: "poll response data member 1 unsupported type: poll",
		},

		"pollResponse with unexpected data": {
			gdmData: Data{
				Type:             PollResponse,
				PollResponseData: []Data{},
				EventData:        objectToRaw(t, Object{"foo": "bar"}),
			},
			expectedError: "field EventData should not be defined",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			bytes, err := tc.gdmData.JSON()
			if tc.expectedError != "" {
				require.ErrorContains(t, err, tc.expectedError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedJSON, string(bytes))

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

		expectedData  Data
		expectedError string
	}{
		"empty": {
			expectedError: "unexpected end of JSON input",
		},

		"empty object": {
			JSON:          `{}`,
			expectedError: "unexpected type unknownType",
		},

		"hello": {
			JSON:         `{"type":"hello"}`,
			expectedData: Data{Type: Hello},
		},

		"hello with data": {
			JSON:         `{"type":"hello","helloData":{"version":55}}`,
			expectedData: Data{Type: Hello, HelloData: &HelloData{Version: 55}},
		},

		"hello with unexpected data": {
			JSON:          `{"type":"hello","requestType":"updateBrokersList"}`,
			expectedError: "field RequestType should not be defined",
		},

		"event": {
			JSON: `{"type":"event","eventType":"brokerSelected",` +
				`"eventData":{"name":"foo"}}`,
			expectedData: Data{
				Type: Event, EventType: BrokerSelected,
				EventData: objectToRaw(t, Object{"name": "foo"}),
			},
		},

		"event with capital name": {
			JSON: `{"type":"event","eventType":"uiLayoutReceived",` +
				`"eventData":{"name":"bar"}}`,
			expectedData: Data{
				Type: Event, EventType: UILayoutReceived,
				EventData: objectToRaw(t, Object{"name": "bar"}),
			},
		},

		"event with missing type": {
			JSON:          `{"type":"event","eventData":{"name":"foo"}}`,
			expectedError: "missing event type",
		},

		"event with unknown type": {
			JSON:          `{"type":"event","eventData":{"name":"foo"},"eventType":"someType"}`,
			expectedError: "missing event type",
		},

		"event with missing data": {
			JSON:          `{"type":"event","eventType":"brokerSelected"}`,
			expectedError: "missing event data",
		},

		"event with unexpected data": {
			JSON: `{"type":"event","eventType":"brokerSelected",` +
				`"eventData":{"name":"foo"},"requestType":"updateBrokersList"}`,
			expectedError: "field RequestType should not be defined",
		},

		"event ack": {
			JSON:         `{"type":"eventAck"}`,
			expectedData: Data{Type: EventAck},
		},

		"event ack with unexpected member": {
			JSON:          `{"type":"eventAck","eventData":{"name":"foo"}}`,
			expectedError: "field EventData should not be defined",
		},

		"request": {
			JSON: `{"type":"request","requestType":"uiLayoutCapabilities",` +
				`"requestData":{"name":"foo"}}`,
			expectedData: Data{
				Type: Request, RequestType: UILayoutCapabilities,
				RequestData: Object{"name": "foo"},
			},
		},

		"request with missing type": {
			JSON:          `{"type":"request","requestData":{"name":"foo"}}`,
			expectedError: "missing request type",
		},

		"request with unknown type": {
			JSON: `{"type":"request","requestType":"someUnknownRequest",` +
				`"requestData":{"name":"foo"}}`,
			expectedError: "missing request type",
		},

		"request with missing data": {
			JSON:         `{"type":"request","requestType":"updateBrokersList"}`,
			expectedData: Data{Type: Request, RequestType: UpdateBrokersList},
		},

		"request with unexpected data": {
			JSON: `{"type":"request","requestType":"uiLayoutCapabilities",` +
				`"requestData":{"name":"foo"}, "eventType":"brokerSelected"}`,
			expectedError: "field EventType should not be defined",
		},

		"response": {
			JSON: `{"type":"response","responseData":[{"name":"foo"},{"name":"bar"}]}`,
			expectedData: Data{
				Type:         Response,
				ResponseData: valuesToRawJSON(t, Object{"name": "foo"}, Object{"name": "bar"}),
			},
		},

		"response with empty data": {
			JSON: `{"type":"response","responseData":[]}`,
			expectedData: Data{
				Type:         Response,
				ResponseData: valuesToRawJSON(t),
			},
			ignoreReconversion: true,
		},

		"response with mixed data": {
			JSON: `{"type":"response","responseData":[{"name":"foo"},true,"string",12345,0.55]}`,
			expectedData: Data{
				Type: Response,
				ResponseData: valuesToRawJSON(t,
					Object{"name": "foo"}, true, "string", 12345, 0.55,
				),
			},
		},

		"response with missing data": {
			JSON:          `{"type":"response"}`,
			expectedError: "missing response data",
		},

		"response with unexpected data": {
			JSON:          `{"type":"response","responseData":[], "eventType":"brokerSelected"}`,
			expectedError: "field EventType should not be defined",
		},

		"poll": {
			JSON:         `{"type":"poll"}`,
			expectedData: Data{Type: Poll},
		},

		"poll with unexpected data": {
			JSON:          `{"type":"poll", "responseData": []}`,
			expectedError: "field ResponseData should not be defined",
		},

		"pollResponse": {
			JSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}}]}`,
			expectedData: Data{
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

		"pollResponse with empty data": {
			JSON: `{"type":"pollResponse"}`,
			expectedData: Data{
				Type:             PollResponse,
				PollResponseData: nil,
			},
		},

		"pollResponse with missing event type": {
			JSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}},` +
				`{"type":"event","eventData":{"foo":"bar"}}]}`,
			expectedError: "poll response data member 1 invalid: missing event type",
		},

		"pollResponse with unsupported data type": {
			JSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}},` +
				`{"type":"poll"}]}`,
			expectedError: "poll response data member 1 unsupported type: poll",
		},

		"pollResponse with unexpected data": {
			JSON: `{"type":"pollResponse","pollResponseData":` +
				`[{"type":"event","eventType":"brokerSelected","eventData":{"foo":"bar"}}],` +
				`"responseData": []}`,
			expectedError: "field ResponseData should not be defined",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gdmData, err := NewDataFromJSON([]byte(tc.JSON))
			if tc.expectedError != "" {
				require.ErrorContains(t, err, tc.expectedError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedData, *gdmData)

			if !tc.ignoreReconversion {
				json, err := gdmData.JSON()
				require.NoError(t, err)
				require.Equal(t, tc.JSON, string(json))
			}
		})
	}
}

type rawValuesParser interface {
	rawJSONToAny(t *testing.T, msg json.RawMessage) (any, error)
}

type typedParser[T any] struct{}

func (s *typedParser[T]) rawJSONToAny(t *testing.T, msg json.RawMessage) (any, error) {
	t.Helper()
	val, err := ParseRawJSON[T](msg)
	if err != nil {
		return nil, err
	}
	require.NotNil(t, val)
	return *val, err
}

func TestParseRawJSON(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		value          any
		specificParser rawValuesParser
	}{
		"nil": {
			value: nil,
		},

		"simple values": {
			value: []any{nil, true, 123.45, "yeah!"},
		},

		"empty object": {
			value:          Object{},
			specificParser: &typedParser[Object]{},
		},

		"filled object": {
			value: Object{
				"nil":     nil,
				"bool":    true,
				"numeric": 123.45,
				"stringy": "yeah!",
			},
			specificParser: &typedParser[Object]{},
		},

		"event": {
			value: Data{
				Type:      Event,
				EventType: AuthEvent,
				EventData: objectToRaw(t, map[string]any{"uno": 1}),
			},
			specificParser: &typedParser[Data]{},
		},

		"response data": {
			value: Data{
				Type: Response,
				ResponseData: valuesToRawJSON(t, nil, true, "foo", 134.45,
					[]string{"a", "b", "c"}),
			},
			specificParser: &typedParser[Data]{},
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rawValue := valueToRawJSON(t, tc.value)
			if tc.specificParser != nil {
				parsedValue, err := tc.specificParser.rawJSONToAny(t, rawValue)
				require.NoError(t, err)
				require.Equal(t, tc.value, parsedValue)
				return
			}

			value, err := ParseRawJSON[any](rawValue)
			require.NoError(t, err)
			require.NotNil(t, value)
			require.Equal(t, tc.value, *value)
		})
	}
}

func TestParseRawJSONFailures(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		value          any
		specificParser rawValuesParser
	}{
		"simple values": {
			value:          []any{nil, true, 123.45, "yeah!"},
			specificParser: &typedParser[[]int]{},
		},

		"empty object": {
			value:          Object{},
			specificParser: &typedParser[string]{},
		},

		"filled object": {
			value: Object{
				"nil":     nil,
				"bool":    true,
				"numeric": 123.45,
				"stringy": "yeah!",
			},
			specificParser: &typedParser[[]string]{},
		},

		"event": {
			value: Data{
				Type:      Event,
				EventType: AuthEvent,
				EventData: objectToRaw(t, map[string]any{"uno": 1}),
			},
			specificParser: &typedParser[int]{},
		},

		"response data": {
			value: Data{
				Type: Response,
				ResponseData: valuesToRawJSON(t, nil, true, "foo", 134.45,
					[]string{"a", "b", "c"}),
			},
			specificParser: &typedParser[float32]{},
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rawValue := valueToRawJSON(t, tc.value)
			parsedValue, err := tc.specificParser.rawJSONToAny(t, rawValue)
			require.Error(t, err)
			require.Nil(t, parsedValue)
		})
	}
}
