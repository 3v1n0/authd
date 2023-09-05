package gdm

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
)

const (
	// ProtoVersion is the version of the JSON protocol.
	ProtoVersion = int(1)
)

// DataType represents the type of a communication event.
type DataType int

// Object is the type for any generic object data value.
type Object = map[string]any

// Data is the serializable structure that can be passed to Gdm and that
// we expect gdm to return us.
type Data struct {
	Type             DataType    `json:"type"`
	HelloData        *HelloData  `json:"helloData,omitempty"`
	RequestType      RequestType `json:"requestType,omitempty"`
	RequestData      Object      `json:"requestData,omitempty"`
	ResponseData     []Object    `json:"responseData,omitempty"`
	PollResponseData []Data      `json:"pollResponseData,omitempty"`
	EventType        EventType   `json:"eventType,omitempty"`
	EventData        Object      `json:"eventData,omitempty"`
}

// NewDataFromJSON unmarshals data from json bytes.
func NewDataFromJSON(bytes []byte) (*Data, error) {
	var gdmData Data
	if err := json.Unmarshal(bytes, &gdmData); err != nil {
		return nil, err
	}

	if err := gdmData.Check(); err != nil {
		return nil, err
	}

	return &gdmData, nil
}

func (d Data) checkMembers(acceptedMembers []string) error {
	val := reflect.ValueOf(d)
	typ := val.Type()
	acceptedMembers = append(acceptedMembers, "Type")

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		if slices.Contains(acceptedMembers, fieldType.Name) {
			continue
		}

		if !field.IsZero() {
			return fmt.Errorf("field %v should not be defined", fieldType.Name)
		}
	}

	return nil
}

// Check allows to check the sanity of a data value
func (d Data) Check() error {
	switch d.Type {
	case UnknownType:
		return fmt.Errorf("unexpected type %v", d.Type.String())

	case Hello:
		if err := d.checkMembers([]string{"HelloData"}); err != nil {
			return err
		}

	case Event:
		if d.EventType == UnknownEvent {
			return fmt.Errorf("missing event type")
		}
		if d.EventData == nil {
			return fmt.Errorf("missing event data")
		}
		if err := d.checkMembers([]string{"EventType", "EventData"}); err != nil {
			return err
		}

	case Request:
		if d.RequestType == UnknownRequest {
			return fmt.Errorf("missing request type")
		}
		if err := d.checkMembers([]string{"RequestType", "RequestData"}); err != nil {
			return err
		}

	case Response:
		if d.ResponseData == nil {
			return fmt.Errorf("missing response data")
		}
		if err := d.checkMembers([]string{"ResponseData"}); err != nil {
			return err
		}

	case Poll:
		if err := d.checkMembers([]string{}); err != nil {
			return err
		}

	case PollResponse:
		if err := d.checkMembers([]string{"PollResponseData"}); err != nil {
			return err
		}
		for i, response := range d.PollResponseData {
			switch response.Type {
			case Event:
			default:
				return fmt.Errorf("poll response data member %v unsupported type: %v",
					i, response.Type.String())
			}
			if err := response.Check(); err != nil {
				return fmt.Errorf("poll response data member %v invalid: %v", i, err)
			}
		}

	default:
		return fmt.Errorf("unhandled type %v", d.Type)
	}

	return nil
}

// JSON returns the data object serialized as JSON bytes.
func (d *Data) JSON() ([]byte, error) {
	bytes, err := json.Marshal(d)
	if err != nil {
		return []byte{}, err
	}

	if err = d.Check(); err != nil {
		return []byte{}, err
	}

	return bytes, err
}

const (
	// UnknownType is an unknown DataType.
	UnknownType DataType = iota
	// Hello is an hello DataType.
	Hello
	// Event is an event DataType.
	Event
	// Request is a request DataType.
	Request
	// Response is a response DataType.
	Response
	// Poll is a poll DataType.
	Poll
	// PollResponse is a poll response DataType.
	PollResponse
)

func (t DataType) String() string {
	switch t {
	case Hello:
		return "hello"
	case Event:
		return "event"
	case Request:
		return "request"
	case Response:
		return "response"
	case Poll:
		return "poll"
	case PollResponse:
		return "pollResponse"
	default:
		return "unknownEvent"
	}
}

// UnmarshalJSON unmarshals a DataType from json bytes.
func (t *DataType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case "hello":
		*t = Hello
	case "event":
		*t = Event
	case "request":
		*t = Request
	case "response":
		*t = Response
	case "poll":
		*t = Poll
	case "pollResponse":
		*t = PollResponse
	default:
		*t = UnknownType
	}

	return nil
}

// MarshalJSON marshals DataType to JSON bytes.
func (t DataType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// HelloData represents the struct type for an Hello message.
type HelloData struct {
	Version int `json:"version"`
}

// EventType defines the types for the events that we support.
type EventType int

const (
	// UnknownEvent is an unknown EventType
	UnknownEvent EventType = iota
	// UserSelected is an user selected EventType
	UserSelected
	// BrokerSelected is a broker selected EventType
	BrokerSelected
	// AuthModeSelected is an auth mode-selected EventType
	AuthModeSelected
	// AuthEvent is an auth event EventType
	AuthEvent
)

func (e EventType) String() string {
	switch e {
	case UserSelected:
		return "userSelected"
	case BrokerSelected:
		return "brokerSelected"
	case AuthModeSelected:
		return "authModeSelected"
	case AuthEvent:
		return "authEvent"
	default:
		return ""
	}
}

// UnmarshalJSON unmarshals a EventType from json bytes.
func (e *EventType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case "userSelected":
		*e = UserSelected
	case "brokerSelected":
		*e = BrokerSelected
	case "authModeSelected":
		*e = AuthModeSelected
	case "authEvent":
		*e = AuthEvent
	default:
		*e = UnknownEvent
	}

	return nil
}

// MarshalJSON marshals EventType to JSON bytes.
func (e EventType) MarshalJSON() ([]byte, error) {
	var s string
	switch e {
	case UserSelected:
		s = "userSelected"
	case BrokerSelected:
		s = "brokerSelected"
	case AuthModeSelected:
		s = "authModeSelected"
	case AuthEvent:
		s = "authEvent"
	default:
		s = "unknownEvent"
	}

	return json.Marshal(s)
}

// RequestType represents the the supported requests.
type RequestType int

const (
	// UnknownRequest is an unknown request RequestType.
	UnknownRequest RequestType = iota
	// UpdateBrokersList is an update brokers list RequestType.
	UpdateBrokersList
	// ComposeAuthenticationView is an compose authentication view RequestType.
	ComposeAuthenticationView
	// UILayoutCapabilities is an ui layout capabilities RequestType.
	UILayoutCapabilities
)

// UnmarshalJSON unmarshals a RequestType from json bytes.
func (r *RequestType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case "updateBrokersList":
		*r = UpdateBrokersList
	case "composeAuthenticationView":
		*r = ComposeAuthenticationView
	case "uiLayoutCapabilities":
		*r = UILayoutCapabilities
	default:
		*r = UnknownRequest
	}

	return nil
}

// MarshalJSON marshals RequestType to JSON bytes.
func (r RequestType) MarshalJSON() ([]byte, error) {
	var s string
	switch r {
	case UpdateBrokersList:
		s = "updateBrokersList"
	case ComposeAuthenticationView:
		s = "composeAuthenticationView"
	case UILayoutCapabilities:
		s = "uiLayoutCapabilities"
	default:
		s = "unknownRequest"
	}

	return json.Marshal(s)
}
