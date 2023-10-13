package gdm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGdmStructsMarshal(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		gdmData            Data
		expectedJSON       string
		shouldFail         bool
		expectedError      string
		ignoreReconversion bool
	}{
		"empty": {
			expectedError: "unexpected type unknownEvent",
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
				EventData: Object{"name": "foo"},
			},
			expectedJSON: `{"type":"event","eventType":"brokerSelected",` +
				`"eventData":{"name":"foo"}}`,
		},

		"event with unknown type": {
			gdmData:       Data{Type: Event, EventType: UnknownEvent},
			expectedError: "missing event type",
		},

		"event with missing data": {
			gdmData:       Data{Type: Event, EventType: UserSelected},
			expectedError: "missing event data",
		},

		"event with unexpected data": {
			gdmData: Data{
				Type: Event, EventType: BrokerSelected,
				EventData:   Object{"name": "foo"},
				RequestData: Object{"foo": "bar"},
			},
			expectedError: "field RequestData should not be defined",
		},

		"request": {
			gdmData: Data{
				Type: Request, RequestType: UiLayoutCapabilities,
				RequestData: Object{"name": "foo"},
			},
			expectedJSON: `{"type":"request","requestType":"uiLayoutCapabilities",` +
				`"requestData":{"name":"foo"}}`,
		},

		"request with unknown type": {
			gdmData:       Data{Type: Request, RequestType: UnknownRequest},
			expectedError: "missing request type",
		},

		"request with missing data": {
			gdmData:      Data{Type: Request, RequestType: UpdateBrokersList},
			expectedJSON: `{"type":"request","requestType":"updateBrokersList"}`,
		},

		"request with unexpected data": {
			gdmData: Data{
				Type: Request, RequestType: UiLayoutCapabilities,
				RequestData: Object{"name": "foo"},
				EventData:   Object{"foo": "bar"},
			},
			expectedError: "field EventData should not be defined",
		},

		"response": {
			gdmData: Data{
				Type:         Response,
				ResponseData: []Object{{"name": "foo"}, {"name": "bar"}},
			},
			expectedJSON: `{"type":"response","responseData":[{"name":"foo"},{"name":"bar"}]}`,
		},

		"response with empty data": {
			gdmData: Data{
				Type:         Response,
				ResponseData: []Object{},
			},
			expectedJSON:       `{"type":"response"}`,
			ignoreReconversion: true,
		},

		"response with missing data": {
			gdmData:       Data{Type: Response},
			expectedError: "missing response data",
		},

		"response with unexpected data": {
			gdmData: Data{
				Type:         Response,
				ResponseData: []Object{{"name": "foo"}},
				EventData:    Object{"foo": "bar"},
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
						EventData: Object{"foo": "bar"},
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
						EventData: Object{"foo": "bar"},
					},
					{
						Type:      Event,
						EventData: Object{"broken": "yes"},
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
						EventData: Object{"foo": "bar"},
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
				EventData:        Object{"foo": "bar"},
			},
			expectedError: "field EventData should not be defined",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			bytes, err := tc.gdmData.JSON()
			if tc.shouldFail || tc.expectedError != "" {
				if tc.expectedError != "" {
					require.ErrorContains(t, err, tc.expectedError)
				} else {
					require.Error(t, err)
				}
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
		expectedData       Data
		shouldFail         bool
		expectedError      string
		ignoreReconversion bool
	}{
		"empty": {
			expectedError: "unexpected end of JSON input",
		},

		"empty object": {
			JSON:          `{}`,
			expectedError: "unexpected type unknownEvent",
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
				EventData: Object{"name": "foo"},
			},
		},

		"event with unknown type": {
			JSON:          `{"type":"event","eventData":{"name":"foo"}}`,
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

		"request": {
			JSON: `{"type":"request","requestType":"uiLayoutCapabilities",` +
				`"requestData":{"name":"foo"}}`,
			expectedData: Data{
				Type: Request, RequestType: UiLayoutCapabilities,
				RequestData: Object{"name": "foo"},
			},
		},

		"request with unknown type": {
			JSON: `{"type":"request","requestType":"unknownRequest",` +
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
				ResponseData: []Object{{"name": "foo"}, {"name": "bar"}},
			},
		},

		"response with empty data": {
			JSON: `{"type":"response","responseData":[]}`,
			expectedData: Data{
				Type:         Response,
				ResponseData: []Object{},
			},
			ignoreReconversion: true,
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
						EventData: Object{"foo": "bar"},
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
			ignoreReconversion: true,
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
			gdmData, err := NewDataFromJSON([]byte(tc.JSON))
			if tc.shouldFail || tc.expectedError != "" {
				if tc.expectedError != "" {
					require.ErrorContains(t, err, tc.expectedError)
				} else {
					require.Error(t, err)
				}
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
