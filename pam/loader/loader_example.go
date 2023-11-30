package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/gdm"
)

var currentStage int

func valuesToRawJSON[T any](values []T) []json.RawMessage {
	rawValues := make([]json.RawMessage, len(values))
	for i, value := range values {
		bytes, err := json.Marshal(value)
		if err != nil {
			panic(err)
		}
		rawValues[i] = bytes
	}
	return rawValues
}

func exampleHandleGdmData(gdmData *gdm.Data) (*gdm.Data, error) {
	log.Debugf(context.TODO(), "Handling authd protocol: %#v", gdmData)

	switch gdmData.Type {
	case gdm.DataType_hello:
		return &gdm.Data{
			Type:  gdm.DataType_hello,
			Hello: &gdm.HelloData{Version: gdm.ProtoVersion},
		}, nil

	case gdm.DataType_request:
		return exampleHandleAuthDRequest(gdmData)

	case gdm.DataType_poll:
		return &gdm.Data{
			Type:         gdm.DataType_pollResponse,
			PollResponse: []*gdm.EventData{},
		}, nil

	case gdm.DataType_event:
		return &gdm.Data{
			Type: gdm.DataType_eventAck,
		}, nil
	}

	return nil, fmt.Errorf("unhandled protocol message %s",
		gdmData.Type.String())
}

func exampleHandleAuthDRequest(gdmData *gdm.Data) (*gdm.Data, error) {
	switch gdmData.Request.Type {
	case gdm.RequestType_uiLayoutCapabilities:
		required, _ := "required", "optional"
		supportedEntries := "optional:chars,chars_password"
		// requiredWithBooleans := "required:true,false"
		optionalWithBooleans := "optional:true,false"

		return &gdm.Data{
			Type: gdm.DataType_response,
			Response: &gdm.ResponseData{
				Type: gdmData.Request.Type,
				Data: &gdm.ResponseData_UiLayoutCapabilities{
					UiLayoutCapabilities: &gdm.Responses_UiLayoutCapabilities{
						SupportedUiLayouts: []*authd.UILayout{
							{
								Type:  "form",
								Label: &required,
								Entry: &supportedEntries,
								Wait:  &optionalWithBooleans,
								// Button: &optional,
							},
							{
								Type:  "newpassword",
								Label: &required,
								Entry: &supportedEntries,
								// Button: &optional,
							},
						},
					},
				},
			},
		}, nil

	case gdm.RequestType_changeStage:
		if gdmData.Request.Data == nil {
			return nil, fmt.Errorf("missing stage data")
		}
		s := gdmData.Request.Data.(*gdm.RequestData_ChangeStage).ChangeStage.Stage
		currentStage = int(s)
		log.Debugf(context.TODO(), "Switching to stage %d", currentStage)

		return &gdm.Data{
			Type: gdm.DataType_response,
			Response: &gdm.ResponseData{
				Type: gdmData.Request.Type,
				Data: &gdm.ResponseData_Ack{},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown request type")
	}
}
