package gdm

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"time"
)

const (
	// ProtoVersion is the version of the JSON protocol.
	ProtoVersion = int(1)
)

// FIXME: use this
// import _ "golang.org/x/tools/cmd/stringer"

// DataType represents the type of a communication event.
type DataType int

// Object is the type for any generic object data value.
type Object map[string]any

// ToRawMessage generates a gdm.RawObject from an Object.
func (o *Object) ToRawMessage() (RawObject, error) {
	rawObj := RawObject{}
	for key, value := range *o {
		bytes, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		rawObj[key] = json.RawMessage(bytes)
	}
	return rawObj, nil
}

// RawObject is the type for any generic raw object data value.
type RawObject = map[string]json.RawMessage

// Data is the serializable structure that can be passed to Gdm and that
// we expect gdm to return us.
type Data struct {
	Type             DataType          `json:"type"`
	HelloData        *HelloData        `json:"helloData,omitempty"`
	RequestType      RequestType       `json:"requestType,omitempty"`
	RequestData      Object            `json:"requestData,omitempty"`
	ResponseData     []json.RawMessage `json:"responseData,omitempty"`
	PollResponseData []Data            `json:"pollResponseData,omitempty"`
	EventType        EventType         `json:"eventType,omitempty"`
	EventData        RawObject         `json:"eventData,omitempty"`
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

	case EventAck:
		if err := d.checkMembers([]string{}); err != nil {
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
				time.Sleep(time.Minute * 5)
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
	// EventAck is an event DataType.
	EventAck
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
	case EventAck:
		return "eventAck"
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
	case "eventAck":
		*t = EventAck
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
	// UnknownEvent is an unknown EventType.
	UnknownEvent EventType = iota
	// UserSelected is an user selected EventType.
	UserSelected
	// BrokersReceived is a broker received EventType.
	BrokersReceived
	// BrokerSelected is a broker selected EventType.
	BrokerSelected
	// AuthModesReceived is an auth modes received EventType.
	AuthModesReceived
	// AuthModeSelected is an auth mode selected EventType.
	AuthModeSelected
	// ReselectAuthMode is an reselect auth mode selected EventType.
	ReselectAuthMode
	// AuthEvent is an auth event EventType.
	AuthEvent
	// UILayoutReceived is an UI Layout Received EventType.
	UILayoutReceived
	// StartAuthentication is a start authentication EventType.
	StartAuthentication
	// IsAuthenticatedRequested is an authentication request EventType.
	IsAuthenticatedRequested
	// StageChanged is stage changed EventType.
	StageChanged
)

func (e EventType) String() string {
	switch e {
	case UserSelected:
		return "userSelected"
	case BrokerSelected:
		return "brokerSelected"
	case AuthModesReceived:
		return "authModesReceived"
	case AuthModeSelected:
		return "authModeSelected"
	case ReselectAuthMode:
		return "reselectAuthMode"
	case AuthEvent:
		return "authEvent"
	case BrokersReceived:
		return "brokersReceived"
	case UILayoutReceived:
		return "uiLayoutReceived"
	case StartAuthentication:
		return "startAuthentication"
	case IsAuthenticatedRequested:
		return "isAuthenticatedRequested"
	case StageChanged:
		return "stageChanged"
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
	case "authModesReceived":
		*e = AuthModesReceived
	case "authModeSelected":
		*e = AuthModeSelected
	case "authEvent":
		*e = AuthEvent
	case "brokersReceived":
		*e = BrokersReceived
	case "uiLayoutReceived":
		*e = UILayoutReceived
	case "startAuthentication":
		*e = StartAuthentication
	case "isAuthenticatedRequested":
		*e = IsAuthenticatedRequested
	case "reselectAuthMode":
		*e = ReselectAuthMode
	case "stageChanged":
		*e = StageChanged
	default:
		*e = UnknownEvent
	}

	return nil
}

// MarshalJSON marshals EventType to JSON bytes.
func (e EventType) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
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
	// ChangeStage is a change stage RequestType.
	ChangeStage
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

func (r RequestType) String() string {
	switch r {
	case UpdateBrokersList:
		return "updateBrokersList"
	case ComposeAuthenticationView:
		return "composeAuthenticationView"
	case UILayoutCapabilities:
		return "uiLayoutCapabilities"
	case ChangeStage:
		return "changeStage"
	default:
		return "unknownRequest"
	}
}

// MarshalJSON marshals RequestType to JSON bytes.
func (r RequestType) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// ItemNotFound defines is the error when an item is not found in an object.
type ItemNotFound struct {
	error
}

// Is ensures that we check on error type more on its message
func (ItemNotFound) Is(target error) bool { return target == ItemNotFound{} }

// // ParseObject allows to parse an object value into a parsed structure.
// func ParseObject[T any](o Object, item string) (*T, error) {
// 	parsed := new(T)
// 	if err := ParseObjectTo(o, item, parsed); err != nil {
// 		return nil, err
// 	}
// 	return parsed, nil
// }

// // ParseObjectTo allows to parse an object value into a parsed structure.
// func ParseObjectTo[T any](o Object, item string, dest *T) error {
// 	value, ok := o[item]
// 	if !ok {
// 		return ItemNotFound{fmt.Errorf("no item '%s' found", item)}
// 	}
// 	// Using mapstructure would be nicer here, but it would require also do
// 	// more mappings that we already did for JSON, so let's just do the
// 	// conversion back and forth twice. It's not too bad.
// 	bytes, err := json.Marshal(value)
// 	if err != nil {
// 		return fmt.Errorf("parsing GDM object failed: %w", err)
// 	}
// 	if err := json.Unmarshal(bytes, dest); err != nil {
// 		return fmt.Errorf("parsing GDM object failed: %w", err)
// 	}
// 	return nil
// }

// ParseRawObject allows to parse an object value into a parsed structure.
func ParseRawObject[T any](o RawObject, item string) (*T, error) {
	parsed := new(T)
	if err := ParseRawObjectTo(o, item, parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

// ParseRawObjectTo allows to parse an object value into a parsed structure.
func ParseRawObjectTo[T any](o RawObject, item string, dest *T) error {
	value, ok := o[item]
	if !ok {
		return ItemNotFound{fmt.Errorf("no item '%s' found", item)}
	}
	if err := json.Unmarshal(value, dest); err != nil {
		return fmt.Errorf("parsing GDM object failed: %w", err)
	}
	return nil
}

// ParseRawJSON allows to parse an object value into a parsed structure.
func ParseRawJSON[T any](r json.RawMessage) (*T, error) {
	parsed := new(T)
	if err := ParseRawJSONTo(r, parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

// ParseRawJSONTo allows to parse an object value into a parsed structure.
func ParseRawJSONTo[T any](r json.RawMessage, dest *T) error {
	if err := json.Unmarshal(r, dest); err != nil {
		return fmt.Errorf("parsing GDM object failed: %w", err)
	}
	return nil
}
