package gdm

import "C"

import (
	"errors"
	"fmt"

	"github.com/msteinert/pam/v2"
)

func sendToGdm(pamMTx pam.ModuleTransaction, data []byte) ([]byte, error) {
	binReq, err := NewBinaryJSONProtoRequest(data)
	if err != nil {
		return nil, err
	}
	defer binReq.Release()
	res, err := pamMTx.StartConv(binReq)
	if err != nil {
		return nil, err
	}

	binRes, ok := res.(pam.BinaryConvResponse)
	if !ok {
		return nil, errors.New("returned value is not in binary form")
	}
	defer binRes.Release()
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
	fmt.Println("Got from GDM", string(jsonValue))
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

	switch r := res.(type) {
	case T:
		return r, nil
	case nil:
		return *new(T), nil
	}

	return *new(T), fmt.Errorf("impossible to convert %#v", res)
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
