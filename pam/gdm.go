package main

import (
	"encoding/json"

	"github.com/ubuntu/authd/pam/gdm"
)

func SendGdmAuthdProto(pamh pamHandle, data gdm.Data) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return sendGdmAuthdProtoData(pamh, string(bytes))
}

func SendGdmAuthdProtoParsed(pamh pamHandle, data gdm.Data) (gdm.Data, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return gdm.Data{}, err
	}

	var gdmData gdm.Data
	jsonValue, err := sendGdmAuthdProtoData(pamh, string(bytes))
	err = json.Unmarshal([]byte(jsonValue), &gdmData)
	if err != nil {
		return gdm.Data{}, err
	}
	return gdmData, nil
}
