package main_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/brokers"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/gdm"
	"github.com/ubuntu/authd/pam/internal/gdm_test"
	"github.com/ubuntu/authd/pam/internal/proto"
)

type gdmTestModuleHandler struct {
	t  *testing.T
	tx *pam.Transaction

	protoVersion uint32

	supportedLayouts []*authd.UILayout

	currentStage  proto.Stage
	pollResponses []*gdm.EventData

	authModes           []*authd.GAMResponse_AuthenticationMode
	authModeID          string
	selectedAuthModeIDs []string

	brokersInfos       []*authd.ABResponse_BrokerInfo
	brokerID           string
	selectedBrokerName string

	eventPollResponses map[gdm.EventType][]*gdm.EventData

	pamInfoMessages  []string
	pamErrorMessages []string
}

func (gh *gdmTestModuleHandler) exampleHandleGdmData(gdmData *gdm.Data) (*gdm.Data, error) {
	switch gdmData.Type {
	case gdm.DataType_hello:
		return &gdm.Data{
			Type:  gdm.DataType_hello,
			Hello: &gdm.HelloData{Version: gh.protoVersion},
		}, nil

	case gdm.DataType_request:
		return gh.exampleHandleAuthDRequest(gdmData)

	case gdm.DataType_poll:
		responses := gh.pollResponses
		gh.pollResponses = nil
		return &gdm.Data{
			Type:         gdm.DataType_pollResponse,
			PollResponse: responses,
		}, nil

	case gdm.DataType_event:
		err := gh.exampleHandleEvent(gdmData.Event)
		if err != nil {
			return nil, err
		}
		return &gdm.Data{
			Type: gdm.DataType_eventAck,
		}, nil
	}

	return nil, fmt.Errorf("unhandled protocol message %s",
		gdmData.Type.String())
}

func (gh *gdmTestModuleHandler) exampleHandleEvent(event *gdm.EventData) error {
	events, ok := gh.eventPollResponses[event.Type]
	if ok && len(events) > 0 {
		numEvents := 1
		if baseGroup := gdm_test.EventsGroup(0); events[0].Type >= baseGroup.Type {
			numEvents = int(events[0].Type) - int(baseGroup.Type)
			events = slices.Delete(events, 0, 1)
		}
		pollEvents := slices.Clone(events[0:numEvents])
		gh.eventPollResponses[event.Type] = slices.Delete(events, 0, numEvents)
		gh.t.Logf("HANDLING EVENT %s, responding: %#v, %#v", event.Type, len(pollEvents), pollEvents[0])
		gh.pollResponses = append(gh.pollResponses, pollEvents...)
	} else {
		gh.t.Logf("HANDLING EVENT %s, responding: NO response", event.Type)
	}

	switch ev := event.Data.(type) {
	case *gdm.EventData_BrokersReceived:
		if len(ev.BrokersReceived.BrokersInfos) == 0 {
			return errors.New("no brokers available")
		}
		gh.brokersInfos = ev.BrokersReceived.BrokersInfos

		if gh.selectedBrokerName == ignoredBrokerName {
			return nil
		}

		idx := slices.IndexFunc(gh.brokersInfos, func(bi *authd.ABResponse_BrokerInfo) bool {
			return bi.Name == gh.selectedBrokerName
		})
		if idx < 0 {
			return fmt.Errorf("broker '%s' is not known", gh.selectedBrokerName)
		}

		gh.pollResponses = append(gh.pollResponses, gdm_test.SelectBrokerEvent(gh.brokersInfos[idx].Id))

	case *gdm.EventData_BrokerSelected:
		idx := slices.IndexFunc(gh.brokersInfos, func(broker *authd.ABResponse_BrokerInfo) bool {
			return broker.Id == ev.BrokerSelected.BrokerId
		})
		if idx < 0 {
			return fmt.Errorf("unknown broker: %s", ev.BrokerSelected.BrokerId)
		}
		gh.brokerID = gh.brokersInfos[idx].Id
		gh.t.Logf("Using broker '%s'", gh.brokersInfos[idx].Name)
		require.Equal(gh.t, gh.selectedBrokerName, gh.brokersInfos[idx].Name,
			"Selected broker name does not match expected one")

	case *gdm.EventData_AuthModesReceived:
		gh.authModes = ev.AuthModesReceived.AuthModes

	case *gdm.EventData_AuthModeSelected:
		gh.authModeID = ev.AuthModeSelected.AuthModeId

	case *gdm.EventData_UiLayoutReceived:
		layout := ev.UiLayoutReceived.UiLayout
		if layout.Label != nil {
			gh.t.Logf("%s:", *layout.Label)
		}

	case *gdm.EventData_StartAuthentication:
		idx := slices.IndexFunc(gh.authModes, func(mode *authd.GAMResponse_AuthenticationMode) bool {
			return mode.Id == gh.authModeID
		})
		if idx < 0 {
			return fmt.Errorf("unknown auth mode type: %s", gh.authModeID)
		}
		if len(gh.selectedAuthModeIDs) < 1 {
			return fmt.Errorf("unexpected authentication started with mode '%s', we've nothing to reply",
				gh.authModeID)
		}
		require.Equal(gh.t, gh.selectedAuthModeIDs[0], gh.authModes[idx].Id,
			"Selected authentication mode ID does not match expected one")
		gh.selectedAuthModeIDs = slices.Delete(gh.selectedAuthModeIDs, 0, 1)

	case *gdm.EventData_AuthEvent:
		gh.t.Logf("Authentication event: %s", ev.AuthEvent.Response)
		if msg := ev.AuthEvent.Response.Msg; msg != "" {
			gh.t.Logf("Got message: %s", msg)
		}

		if ev.AuthEvent.Response.Access != brokers.AuthRetry {
			gh.authModeID = ""
		}
	}
	return nil
}

func (gh *gdmTestModuleHandler) exampleHandleAuthDRequest(gdmData *gdm.Data) (*gdm.Data, error) {
	switch req := gdmData.Request.Data.(type) {
	case *gdm.RequestData_UiLayoutCapabilities:
		return &gdm.Data{
			Type: gdm.DataType_response,
			Response: &gdm.ResponseData{
				Type: gdmData.Request.Type,
				Data: &gdm.ResponseData_UiLayoutCapabilities{
					UiLayoutCapabilities: &gdm.Responses_UiLayoutCapabilities{
						SupportedUiLayouts: gh.supportedLayouts,
					},
				},
			},
		}, nil

	case *gdm.RequestData_ChangeStage:
		if gdmData.Request.Data == nil {
			return nil, fmt.Errorf("missing stage data")
		}
		gh.currentStage = req.ChangeStage.Stage
		log.Debugf(context.TODO(), "Switching to stage %d", gh.currentStage)

		// events, ok := gh.eventPollResponses[gdm.EventType_stageChanged]
		// if ok && len(events) > 0 {
		// 	pollResp := events[0]
		// 	gh.eventPollResponses[gdm.EventType_stageChanged] = slices.Delete(events, 0, 1)
		// 	gh.t.Logf("HANDLING EVENT %s, responding: %#v", gdm.EventType_stageChanged, pollResp)
		// 	gh.pollResponses = append(gh.pollResponses, pollResp)
		// } else {
		// 	gh.t.Logf("HANDLING EVENT %s, responding: NO response", gdm.EventType_stageChanged)
		// }

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

// RespondPAMBinary is a dummy conversation callback adapter to implement [pam.BinaryPointerConversationFunc].
func (gh *gdmTestModuleHandler) RespondPAMBinary(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
	return gdm.DataConversationFunc(func(inData *gdm.Data) (*gdm.Data, error) {
		outData, err := gh.exampleHandleGdmData(inData)
		if err != nil {
			json, jsonErr := inData.JSON()
			require.NoError(gh.t, jsonErr, "Binary conversation: Invalid JSON received as input data")
			gh.t.Log("->", string(json))
			gh.t.Logf("Binary conversation: Error handling data: %v", err)
			return nil, err
		}
		if inData.Type == gdm.DataType_poll && len(outData.PollResponse) == 0 {
			return outData, err
		}
		json, err := inData.JSON()
		require.NoError(gh.t, err, "Binary conversation: Invalid JSON received as input data")
		gh.t.Log("->", string(json))
		json, err = outData.JSON()
		require.NoError(gh.t, err, "Binary conversation: Can't convert output data to JSON")
		gh.t.Log("<-", string(json))
		return outData, nil
	}).RespondPAMBinary(ptr)
}

// RespondPAM is a dummy conversation callback adapter to implement [pam.ConversationFunc].
func (gh *gdmTestModuleHandler) RespondPAM(style pam.Style, prompt string) (string, error) {
	switch style {
	case pam.TextInfo:
		gh.t.Logf("GDM PAM Info Message: %s", prompt)
		gh.pamInfoMessages = append(gh.pamInfoMessages, prompt)
	case pam.ErrorMsg:
		gh.t.Logf("GDM PAM Error Message: %s", prompt)
		gh.pamErrorMessages = append(gh.pamInfoMessages, prompt)
	default:
		return "", fmt.Errorf("PAM style %d not implemented", style)
	}
	return "", nil
}

func newGdmTestModuleHandler(t *testing.T, serviceFile string, userName string) *gdmTestModuleHandler {
	t.Helper()

	gh := &gdmTestModuleHandler{t: t}
	tx, err := pam.StartConfDir(filepath.Base(serviceFile), userName, gh, filepath.Dir(serviceFile))
	require.NoError(t, err, "PAM: Error to initialize module")
	require.NotNil(t, tx, "PAM: Transaction is not set")

	gh.tx = tx

	return gh
}
