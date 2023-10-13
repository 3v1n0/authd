package main

import (
	"context"
	"fmt"

	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/gdm"
)

func exampleHandleGdmData(gdmData *gdm.Data) (*gdm.Data, error) {
	log.Debugf(context.TODO(), "Handling authd protocol: %v", gdmData)

	switch gdmData.Type {
	case gdm.Hello:
		return &gdm.Data{
			Type:      gdm.Hello,
			HelloData: &gdm.HelloData{Version: gdm.ProtoWireVersion},
		}, nil

	case gdm.Request:
		return exampleHandleAuthDRequest(gdmData)

	case gdm.Poll:
		return &gdm.Data{
			Type:             gdm.PollResponse,
			PollResponseData: []gdm.Data{},
		}, nil
	}

	return nil, fmt.Errorf("unhandled protocol message %s",
		gdmData.Type.String())
}

func exampleHandleAuthDRequest(gdmData *gdm.Data) (*gdm.Data, error) {
	switch gdmData.RequestType {
	case gdm.UiLayoutCapabilities:
		return &gdm.Data{
			Type: gdm.Response,
			ResponseData: []gdm.Object{
				{
					"supportedUiLayouts": []string{
						"label",
						"button",
						"entry",
					},
				},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown request type")
	}
}
