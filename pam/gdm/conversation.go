package gdm

import "C"

import (
	"errors"
	"fmt"

	"github.com/msteinert/pam"
)

func sendToGdm(pamMTx pam.ModuleTransaction, data []byte) ([]byte, error) {
	binReq, err := NewBinaryJSONProtoRequest(data)
	if err != nil {
		return nil, err
	}
	defer binReq.Release()
	// fmt.Println("Sending to GDM\n", hex.Dump(data))
	res, err := pamMTx.StartConv(binReq)
	// fmt.Println("Sending ptr", binReq.Pointer())
	if err != nil {
		return nil, err
	}

	binRes, ok := res.(pam.BinaryConvResponse)
	if !ok {
		return nil, errors.New("returned value is not in binary form")
	}
	defer binRes.Release()
	// if _, ok := res.(*pam.BinaryConvResponse); ok {
	// 	return binRes.Decode(func(ptr pam.BinaryPointer) ([]byte, error) {
	// 		msg := (*jsonProtoMessage)(unsafe.Pointer(*(**[]byte)(ptr)))
	// 		return decodeJsonProtoMessage(pam.BinaryPointer(msg))
	// 	})
	// }
	return binRes.Decode(decodeJSONProtoMessage)
}

// Send sends the data to the PAM Module, returning the JSON data.
func (d *Data) Send(pamMTx pam.ModuleTransaction) ([]byte, error) {
	bytes, err := d.JSON()
	if err != nil {
		return nil, err
	}

	return sendToGdm(pamMTx, bytes)
}

// SendParsed sends the data to the PAM Module and returns the parsed Data.
func (d *Data) SendParsed(pamMTx pam.ModuleTransaction) (*Data, error) {
	bytes, err := d.JSON()
	if err != nil {
		return nil, err
	}

	fmt.Println("Sending to GDM", string(bytes))
	jsonValue, err := sendToGdm(pamMTx, bytes)
	if err != nil {
		return nil, err
	}

	gdmData, err := NewDataFromJSON(jsonValue)
	if err != nil {
		return nil, err
	}
	return gdmData, nil
}

// SendPoll sends a PollEvent to Gdm.
func SendPoll(pamMTx pam.ModuleTransaction) ([]*EventData, error) {
	gdmData, err := (&Data{Type: DataType_poll}).SendParsed(pamMTx)
	if err != nil {
		return nil, err
	}

	if gdmData.Type != DataType_pollResponse {
		return nil, fmt.Errorf("gdm replied with an unexpected type: %v",
			gdmData.Type.String())
	}
	return gdmData.GetPollResponse(), nil
}

// type RawResponse RawObject

// func (r *RawResponse) GetItem(item string) (*Object, error) {
// 	rawItem, ok := (*r)[item]
// 	if !ok {
// 		return nil, fmt.Errorf("item '%s' not found in response", item)
// 	}
// 	var object *Object
// 	if err := json.Unmarshal(rawItem, object); err != nil {
// 		return nil, err
// 	}
// 	return object, nil
// }

// SendRequest sends a Request to Gdm.
func SendRequest(pamMTx pam.ModuleTransaction, req Request) (Response, error) {
	var reqType RequestType
	switch req.(type) {
	case *RequestData_UiLayoutCapabilities:
		reqType = RequestType_uiLayoutCapabilities
	case *RequestData_ChangeStage:
		reqType = RequestType_changeStage
	default:
		return nil, fmt.Errorf("no known request type %#v", req)
	}
	gdmData, err := (&Data{
		Type:    DataType_request,
		Request: &RequestData{Type: reqType, Data: req},
	}).SendParsed(pamMTx)

	if err != nil {
		return nil, err
	}

	if gdmData.Type != DataType_response {
		return nil, fmt.Errorf("gdm replied with an unexpected type: %v",
			gdmData.Type.String())
	}
	if gdmData.Response == nil {
		return nil, fmt.Errorf("gdm replied with no response")
	}
	if gdmData.Response.Type != reqType {
		return nil, fmt.Errorf("gdm replied with invalid response type: %v for %v request",
			gdmData.Response.Type, reqType)
	}
	return gdmData.Response.GetData(), nil
}

// SendRequestTyped allows to parse an object value into a parsed structure.
func SendRequestTyped[T Response](pamMTx pam.ModuleTransaction, req Request) (T, error) {
	res, err := SendRequest(pamMTx, req)
	if err != nil {
		return *new(T), err
	}
	v, ok := res.(T)
	if !ok {
		return *new(T), fmt.Errorf("impossible to convert %#v", v)
	}

	return v, nil
}

// EmitEvent sends an Event to Gdm.
func EmitEvent(pamMTx pam.ModuleTransaction, event Event) error {
	var evType EventType
	switch event.(type) {
	case *EventData_BrokersReceived:
		evType = EventType_brokersReceived
	case *EventData_BrokerSelected:
		evType = EventType_brokerSelected
	case *EventData_AuthModesReceived:
		evType = EventType_authModesReceived
	case *EventData_AuthModeSelected:
		evType = EventType_authModeSelected
	case *EventData_IsAuthenticatedRequested:
		evType = EventType_isAuthenticatedRequested
	case *EventData_StageChanged:
		evType = EventType_stageChanged
	case *EventData_UiLayoutReceived:
		evType = EventType_uiLayoutReceived
	case *EventData_AuthEvent:
		evType = EventType_authEvent
	case *EventData_ReselectAuthMode:
		evType = EventType_reselectAuthMode
	default:
		return fmt.Errorf("no known event type %#v", event)
	}

	_, err := (&Data{
		Type:  DataType_event,
		Event: &EventData{Type: evType, Data: event},
	}).SendParsed(pamMTx)

	if err != nil {
		return err
	}

	return nil
}
