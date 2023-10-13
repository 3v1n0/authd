package gdm

import (
	"encoding/json"
	"fmt"
	"reflect"

	"golang.org/x/exp/slices"
)

var ProtoName = "authd-json"
var ProtoVersion = int(1)
var ProtoWireVersion = int(1)

// FIXME: use this
// import _ "golang.org/x/tools/cmd/stringer"

type Object = map[string]interface{}
type DataType int

const (
	UnknownType DataType = iota
	Hello
	Event
	Request
	Response
	Poll
	PollResponse
)

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

type HelloData struct {
	Version int `json:"version"`
}

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

func (t DataType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// state represents the stage object.
type EventType int

const (
	UnknownEvent EventType = iota
	UserSelected
	BrokerSelected
	AuthModeSelected
	AuthEvent
)

func (req EventType) String() string {
	switch req {
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

func (a EventType) MarshalJSON() ([]byte, error) {
	var s string
	switch a {
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
	UnknownRequest RequestType = iota
	UpdateBrokersList
	ComposeAuthenticationView
	UiLayoutCapabilities
)

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
		*r = UiLayoutCapabilities
	default:
		*r = UnknownRequest
	}

	return nil
}

func (a RequestType) MarshalJSON() ([]byte, error) {
	var s string
	switch a {
	case UpdateBrokersList:
		s = "updateBrokersList"
	case ComposeAuthenticationView:
		s = "composeAuthenticationView"
	case UiLayoutCapabilities:
		s = "uiLayoutCapabilities"
	default:
		s = "unknownRequest"
	}

	return json.Marshal(s)
}
