package gdm

import (
	"encoding/json"

	"github.com/msteinert/pam"
)

var ProtoName = "authd-json"
var ProtoVersion = int(1)
var ProtoWireVersion = int(1)

type Field = map[string]any
type DataType = string

type Data struct {
	Type DataType `json:"type"`
	Data Field    `json:"data,omitempty"`
}

func sendGdmAuthdProtoData(pamMt pam.ModuleTransaction, data string) (string, error) {
	request := newStringRequest(data)
	res, err := pamMt.StartBinaryConv(request.encode())
	if err != nil {
		return "", err
	}

	decoded, err := res.Decode(decodeResponse)
	return string(decoded), err
}

// Send sends the data to the PAM Module, returning the JSON string
func (d *Data) Send(pamMt pam.ModuleTransaction) (string, error) {
	bytes, err := json.Marshal(d)
	if err != nil {
		return "", err
	}

	return sendGdmAuthdProtoData(pamMt, string(bytes))
}

// SendParsed sends the data to the PAM Module and returns the parsed Data
func (d *Data) SendParsed(pamMt pam.ModuleTransaction) (Data, error) {
	bytes, err := json.Marshal(d)
	if err != nil {
		return Data{}, err
	}

	var gdmData Data
	jsonValue, err := sendGdmAuthdProtoData(pamMt, string(bytes))
	if err != nil {
		return Data{}, err
	}
	err = json.Unmarshal([]byte(jsonValue), &gdmData)
	if err != nil {
		return Data{}, err
	}
	return gdmData, nil
}
