package main

import (
	"fmt"

	"github.com/ubuntu/authd/pam/gdm"
)

// FIXME: add a queue...

// type requestsQueue []string

// func (q *requestsQueue) push(v string) {
// 	*q = append(*q, v)
// }

// func (q *requestsQueue) pop() string {
// 	queue := *q
// 	value := queue[0]
// 	*q = queue[1:]
// 	return value
// }

// func (q requestsQueue) isEmpty() bool {
// 	return len(q) == 0
// }

// func newQueue() *requestsQueue {
// 	return &requestsQueue{}
// }

func SendGdmAuthdProto(pamh pamHandle, data gdm.Data) (string, error) {
	bytes, err := data.JSON()
	if err != nil {
		return "", err
	}

	return sendGdmAuthdProtoData(pamh, string(bytes))
}

func SendGdmAuthdProtoParsed(pamh pamHandle, data gdm.Data) (gdm.Data, error) {
	bytes, err := data.JSON()
	if err != nil {
		return gdm.Data{}, err
	}

	jsonValue, err := sendGdmAuthdProtoData(pamh, string(bytes))
	if err != nil {
		return gdm.Data{}, err
	}
	gdmData, err := gdm.NewDataFromJSON([]byte(jsonValue))
	if err != nil {
		return gdm.Data{}, err
	}
	return *gdmData, nil
}

func SendGdmPoll(pamh pamHandle) ([]gdm.Data, error) {
	gdmData, err := SendGdmAuthdProtoParsed(pamh, gdm.Data{Type: gdm.Poll})

	if err != nil {
		return nil, err
	}

	if gdmData.Type != gdm.PollResponse {
		return nil, fmt.Errorf("gdm replied with an unexpected type: %v",
			gdmData.Type.String())
	}
	return gdmData.PollResponseData, nil
}

func SendGdmRequest(pamh pamHandle, requestType gdm.RequestType, reqData gdm.Object) (
	[]gdm.Object, error) {
	gdmData, err := SendGdmAuthdProtoParsed(pamh, gdm.Data{
		Type:        gdm.Request,
		RequestType: requestType,
		RequestData: reqData,
	})

	if err != nil {
		return nil, err
	}

	if gdmData.Type != gdm.Response {
		return nil, fmt.Errorf("gdm replied with an unexpected type: %v",
			gdmData.Type.String())
	}
	if gdmData.ResponseData == nil {
		return nil, fmt.Errorf("gdm replied with no response")
	}
	return gdmData.ResponseData, nil
}

func SendGdmEvent(pamh pamHandle, requestType gdm.RequestType, reqData gdm.Object) (
	[]gdm.Object, error) {
	gdmData, err := SendGdmAuthdProtoParsed(pamh, gdm.Data{
		Type:        gdm.Request,
		RequestType: requestType,
		RequestData: reqData,
	})

	if err != nil {
		return nil, err
	}

	if gdmData.Type != gdm.Response {
		return nil, fmt.Errorf("gdm replied with an unexpected type: %s",
			gdmData.Type.String())
	}
	return gdmData.ResponseData, nil
}
