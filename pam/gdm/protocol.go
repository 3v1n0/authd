package gdm

import (
	"encoding/json"
	"errors"
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
type Object map[string]any

// ToRawMessage generates a gdm.RawObject from an Object.
func (o *Object) ToRawMessage() (RawObject, error) {
	rawObj := RawObject{}
	for key, value := range *o {
		rawMsg, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		rawObj[key] = rawMsg
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
			return errors.New("missing event type")
		}
		if d.EventType >= lastEventType {
			return fmt.Errorf("unexpected event type %v", d.EventType)
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
			return errors.New("missing request type")
		}
		if d.RequestType >= lastRequestType {
			return fmt.Errorf("unexpected request type %v", d.RequestType)
		}
		if err := d.checkMembers([]string{"RequestType", "RequestData"}); err != nil {
			return err
		}

	case Response:
		if d.ResponseData == nil {
			return errors.New("missing response data")
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

	// lastDataType is the last DataType value, so keep it as such.
	lastDataType
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
		return "unknownType"
	}
}

// UnmarshalJSON unmarshals a DataType from json bytes.
func (t *DataType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	for i := DataType(0); i < lastDataType; i++ {
		if i.String() == s {
			*t = i
			return nil
		}
	}

	*t = UnknownType
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

	// lastEventType is the last EventType value, so keep it as such.
	lastEventType
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
		return "unknownEvent"
	}
}

// UnmarshalJSON unmarshals a EventType from json bytes.
func (e *EventType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	for i := EventType(0); i < lastEventType; i++ {
		if i.String() == s {
			*e = i
			return nil
		}
	}

	*e = UnknownEvent

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

	// lastRequestType is the last RequestType value, so keep it as such.
	lastRequestType
)

// UnmarshalJSON unmarshals a RequestType from json bytes.
func (r *RequestType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	for i := RequestType(0); i < lastRequestType; i++ {
		if i.String() == s {
			*r = i
			return nil
		}
	}

	*r = UnknownRequest
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
