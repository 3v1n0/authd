package gdm

import "C"

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/msteinert/pam"
)

func sendToGdm(pamMt pam.ModuleTransaction, data []byte) ([]byte, error) {
	binReq, err := NewBinaryJSONProtoRequest(data)
	if err != nil {
		return nil, err
	}
	defer binReq.Release()
	// fmt.Println("Sending to GDM\n", hex.Dump(data))
	res, err := pamMt.StartConv(binReq)
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
func (d *Data) Send(pamMt pam.ModuleTransaction) ([]byte, error) {
	bytes, err := d.JSON()
	if err != nil {
		return nil, err
	}

	return sendToGdm(pamMt, bytes)
}

// SendParsed sends the data to the PAM Module and returns the parsed Data.
func (d *Data) SendParsed(pamMt pam.ModuleTransaction) (Data, error) {
	bytes, err := d.JSON()
	if err != nil {
		return Data{}, err
	}

	fmt.Println("Sending to GDM", string(bytes))
	jsonValue, err := sendToGdm(pamMt, bytes)
	if err != nil {
		return Data{}, err
	}

	gdmData, err := NewDataFromJSON(jsonValue)
	if err != nil {
		return Data{}, err
	}
	return *gdmData, nil
}

// SendPoll sends a PollEvent to Gdm.
func SendPoll(pamMt pam.ModuleTransaction) ([]Data, error) {
	gdmData, err := (&Data{Type: Poll}).SendParsed(pamMt)
	if err != nil {
		return nil, err
	}

	if gdmData.Type != PollResponse {
		return nil, fmt.Errorf("gdm replied with an unexpected type: %v",
			gdmData.Type.String())
	}
	return gdmData.PollResponseData, nil
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
func SendRequest(pamMt pam.ModuleTransaction, requestType RequestType, reqData Object) (
	[]json.RawMessage, error) {
	// bytes, err := json.Marshal(reqData)
	// if err != nil {
	// 	return nil, err
	// }
	// rawReq := RawObject{}
	// if err := json.Unmarshal(bytes, &rawReq); err != nil {
	// 	return nil, err
	// }
	gdmData, err := (&Data{
		Type:        Request,
		RequestType: requestType,
		RequestData: reqData,
	}).SendParsed(pamMt)

	if err != nil {
		return nil, err
	}

	if gdmData.Type != Response {
		return nil, fmt.Errorf("gdm replied with an unexpected type: %v",
			gdmData.Type.String())
	}
	if gdmData.ResponseData == nil {
		return nil, fmt.Errorf("gdm replied with no response")
	}
	return gdmData.ResponseData, nil
}

// EmitEvent sends an Event to Gdm.
func EmitEvent(pamMt pam.ModuleTransaction, eventType EventType, evData Object) error {
	rawObject, err := evData.ToRawMessage()
	if err != nil {
		return err
	}
	_, err = (&Data{
		Type:      Event,
		EventType: eventType,
		EventData: rawObject,
	}).SendParsed(pamMt)

	if err != nil {
		return err
	}

	return nil
}
