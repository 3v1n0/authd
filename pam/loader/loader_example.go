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
	case gdm.Hello:
		return &gdm.Data{
			Type:      gdm.Hello,
			HelloData: &gdm.HelloData{Version: gdm.ProtoVersion},
		}, nil

	case gdm.Request:
		return exampleHandleAuthDRequest(gdmData)

	case gdm.Poll:
		return &gdm.Data{
			Type:             gdm.PollResponse,
			PollResponseData: []gdm.Data{},
		}, nil

	case gdm.Event:
		return &gdm.Data{
			Type: gdm.EventAck,
		}, nil
	}

	return nil, fmt.Errorf("unhandled protocol message %s",
		gdmData.Type.String())
}

func exampleHandleAuthDRequest(gdmData *gdm.Data) (*gdm.Data, error) {
	switch gdmData.RequestType {
	case gdm.UILayoutCapabilities:
		required, _ := "required", "optional"
		supportedEntries := "optional:chars,chars_password"
		// requiredWithBooleans := "required:true,false"
		optionalWithBooleans := "optional:true,false"
		return &gdm.Data{
			Type: gdm.Response,
			ResponseData: valuesToRawJSON([]any{
				[]authd.UILayout{
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
			}),
		}, nil

	case gdm.ChangeStage:
		s, ok := gdmData.RequestData["stage"].(float64)
		if !ok {
			return nil, fmt.Errorf("missing stage data")
		}
		currentStage = int(s)
		log.Debugf(context.TODO(), "Switching to stage %d", currentStage)
		return &gdm.Data{
			Type:         gdm.Response,
			ResponseData: valuesToRawJSON([]any{true}),
		}, nil

	default:
		return nil, fmt.Errorf("unknown request type")
	}
}
