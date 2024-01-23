package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/gdm"
	"github.com/ubuntu/authd/pam/internal/pam_test"
	pam_proto "github.com/ubuntu/authd/pam/internal/proto"
	"google.golang.org/grpc"
)

func reformatJSONIndented(t *testing.T, input []byte) []byte {
	t.Helper()

	var indented bytes.Buffer
	err := json.Indent(&indented, input, "", "  ")
	require.NoError(t, err)
	return indented.Bytes()
}

// func requireEqualData(t *testing.T, want *gdm.Data, actual *gdm.Data) {
// 	t.Helper()

// 	wantJSON, err := want.JSON()
// 	require.NoError(t, err)
// 	actualJSON, err := actual.JSON()
// 	require.NoError(t, err)

// 	require.Equal(t, string(reformatJSONIndented(t, wantJSON)),
// 		string(reformatJSONIndented(t, actualJSON)))
// }

func requireEqualData(t *testing.T, want any, actual any) {
	t.Helper()

	wantJSON, err := json.Marshal(want)
	require.NoError(t, err)
	actualJSON, err := json.Marshal(actual)
	require.NoError(t, err)

	require.Equal(t, string(reformatJSONIndented(t, wantJSON)),
		string(reformatJSONIndented(t, actualJSON)))
}

type mockClient struct {
	availableBrokersRet []*authd.ABResponse_BrokerInfo
	availableBrokersErr error

	getPreviousBrokerRet authd.GPBResponse
	getPreviousBrokerErr error

	selectBrokerErr error

	getAuthenticationModesErr error
	getAuthenticationModesRet []*authd.GAMResponse_AuthenticationMode

	selectAuthenticationModeErr error
	isAuthenticatedErr          error
	endSessionErr               error
	setDefaultBrokerForUserErr  error
}

func newDefaultMockClient() *mockClient {
	return &mockClient{
		availableBrokersRet: []*authd.ABResponse_BrokerInfo{
			{
				Id:        "testBroker",
				Name:      "The best broker!",
				BrandIcon: nil,
			},
		},
		getAuthenticationModesRet: []*authd.GAMResponse_AuthenticationMode{
			{
				Id:    "password",
				Label: "Password authentication",
			},
		},
	}
}

// AvailableBrokers simulates AvailableBrokers through gdm protocol.
func (mc *mockClient) AvailableBrokers(ctx context.Context, in *authd.Empty, opts ...grpc.CallOption) (
	*authd.ABResponse, error) {
	fmt.Println("We're at AvailableBrokers")
	if mc.availableBrokersErr != nil {
		return nil, mc.availableBrokersErr
	}
	return &authd.ABResponse{
		BrokersInfos: mc.availableBrokersRet,
	}, nil
}

// GetPreviousBroker simulates GetPreviousBroker through gdm protocol.
func (mc *mockClient) GetPreviousBroker(ctx context.Context, in *authd.GPBRequest, opts ...grpc.CallOption) (
	*authd.GPBResponse, error) {
	fmt.Println("We're at GetPreviousBroker")
	if mc.getPreviousBrokerErr != nil {
		return nil, mc.getPreviousBrokerErr
	}
	return &mc.getPreviousBrokerRet, nil
}

// SelectBroker simulates SelectBroker through gdm protocol.
func (mc *mockClient) SelectBroker(ctx context.Context, in *authd.SBRequest, opts ...grpc.CallOption) (
	*authd.SBResponse, error) {
	fmt.Println("We're at SelectBroker")
	if mc.selectBrokerErr != nil {
		return nil, mc.selectBrokerErr
	}
	return nil, errors.New("not implemented: SelectBroker")
}

// GetAuthenticationModes simulates GetAuthenticationModes through gdm protocol.
func (mc *mockClient) GetAuthenticationModes(ctx context.Context, in *authd.GAMRequest, opts ...grpc.CallOption) (
	*authd.GAMResponse, error) {
	fmt.Println("We're at GetAuthenticationModes")
	if mc.getAuthenticationModesErr != nil {
		return nil, mc.getAuthenticationModesErr
	}
	return &authd.GAMResponse{
		AuthenticationModes: mc.getAuthenticationModesRet,
	}, nil
}

// SelectAuthenticationMode simulates SelectAuthenticationMode through gdm protocol.
func (mc *mockClient) SelectAuthenticationMode(ctx context.Context, in *authd.SAMRequest, opts ...grpc.CallOption) (
	*authd.SAMResponse, error) {
	fmt.Println("We're at SelectAuthenticationMode")
	if mc.selectAuthenticationModeErr != nil {
		return nil, mc.selectAuthenticationModeErr
	}
	return nil, errors.New("not implemented: SelectAuthenticationMode")
}

// IsAuthenticated simulates IsAuthenticated through gdm protocol.
func (mc *mockClient) IsAuthenticated(ctx context.Context, in *authd.IARequest, opts ...grpc.CallOption) (
	*authd.IAResponse, error) {
	fmt.Println("We're at IsAuthenticated")
	if mc.isAuthenticatedErr != nil {
		return nil, mc.isAuthenticatedErr
	}
	return nil, errors.New("not implemented: IsAuthenticated")
}

// EndSession simulates EndSession through gdm protocol.
func (mc *mockClient) EndSession(ctx context.Context, in *authd.ESRequest, opts ...grpc.CallOption) (
	*authd.Empty, error) {
	fmt.Println("We're at EndSession")
	if mc.endSessionErr != nil {
		return nil, mc.endSessionErr
	}
	return nil, errors.New("not implemented: EndSession")
}

// SetDefaultBrokerForUser simulates SetDefaultBrokerForUser through gdm protocol.
func (mc *mockClient) SetDefaultBrokerForUser(ctx context.Context, in *authd.SDBFURequest, opts ...grpc.CallOption) (
	*authd.Empty, error) {
	fmt.Println("We're at SetDefaultBrokerForUser")
	if mc.setDefaultBrokerForUserErr != nil {
		return nil, mc.setDefaultBrokerForUserErr
	}
	return nil, errors.New("not implemented: SetDefaultBrokerForUser")
}

type gdmConvHandler struct {
	receivedRequests []gdm.RequestType
	supportedLayouts []*authd.UILayout
	receivedEvents   []gdm.Event
	pendingEvents    []*gdm.EventData

	currentStage    pam_proto.Stage
	receivedBrokers []*authd.ABResponse_BrokerInfo
}

func (h *gdmConvHandler) RespondPAM(style pam.Style, prompt string) (string, error) {
	switch style {
	case pam.TextInfo:
		fmt.Fprintf(os.Stderr, "GDM PAM Info Message: %s\n", prompt)
	case pam.ErrorMsg:
		fmt.Fprintf(os.Stderr, "GDM PAM Error Message: %s\n", prompt)
	default:
		return "", fmt.Errorf("PAM style %d not implemented", style)
	}
	return "", nil
}

func (h *gdmConvHandler) RespondPAMBinary(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
	return gdm.DataConversationFunc(func(d *gdm.Data) (*gdm.Data, error) {
		json, _ := d.JSON()
		if string(json) != `{"type":"poll"}` {
			fmt.Println("->", string(json))
		}
		ret, err := h.handleGdmData(d)
		if err != nil {
			return nil, err
		}
		json, _ = ret.JSON()
		if string(json) != `{"type":"pollResponse"}` {
			fmt.Println("<-", string(json))
		}
		return ret, nil
	}).RespondPAMBinary(ptr)
}

func (h *gdmConvHandler) handleGdmData(gdmData *gdm.Data) (*gdm.Data, error) {
	log.Debugf(context.TODO(), "Handling authd protocol: %#v", gdmData)

	switch gdmData.Type {
	case gdm.DataType_hello:
		return &gdm.Data{
			Type:  gdm.DataType_hello,
			Hello: &gdm.HelloData{Version: gdm.ProtoVersion},
		}, nil

	case gdm.DataType_request:
		return h.handleAuthDRequest(gdmData)

	case gdm.DataType_poll:
		events := h.pendingEvents
		h.pendingEvents = nil
		return &gdm.Data{
			Type:         gdm.DataType_pollResponse,
			PollResponse: events,
		}, nil

	case gdm.DataType_event:
		h.handleEvent(gdmData.Event)
		return &gdm.Data{
			Type: gdm.DataType_eventAck,
		}, nil
	}

	return nil, fmt.Errorf("unhandled protocol message %s",
		gdmData.Type.String())
}

func (h *gdmConvHandler) handleAuthDRequest(gdmData *gdm.Data) (*gdm.Data, error) {
	h.receivedRequests = append(h.receivedRequests, gdmData.Request.Type)
	switch req := gdmData.Request.Data.(type) {
	case *gdm.RequestData_UiLayoutCapabilities:
		return &gdm.Data{
			Type: gdm.DataType_response,
			Response: &gdm.ResponseData{
				Type: gdmData.Request.Type,
				Data: &gdm.ResponseData_UiLayoutCapabilities{
					UiLayoutCapabilities: &gdm.Responses_UiLayoutCapabilities{
						SupportedUiLayouts: h.supportedLayouts,
					},
				},
			},
		}, nil

	case *gdm.RequestData_ChangeStage:
		log.Infof(context.TODO(), "Switching to stage %d", req.ChangeStage.Stage)
		h.currentStage = req.ChangeStage.Stage

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

func (h *gdmConvHandler) handleEvent(event *gdm.EventData) {
	h.receivedEvents = append(h.receivedEvents, event.Data)
	switch ev := event.Data.(type) {
	case *gdm.EventData_BrokersReceived:
		h.receivedBrokers = ev.BrokersReceived.BrokersInfos
		// c.gc.brokersInfos = ev.BrokersReceived.BrokersInfos
		// c.gc.gotBrokersInfos <- struct{}{}

	case *gdm.EventData_BrokerSelected:
		// c.gc.previousBrokerID = &ev.BrokerSelected.BrokerId
		// c.gc.gotPreviousBroker <- struct{}{}

	case *gdm.EventData_AuthModesReceived:
		// c.gc.gotAuthModes <- ev.AuthModesReceived.AuthModes

	case *gdm.EventData_UiLayoutReceived:
		// c.gc.uiLayoutChan <- ev.UiLayoutReceived.UiLayout
		// close(c.gc.gotUILayout)
		// c.gc.gotUILayout = make(chan struct{})

	case *gdm.EventData_AuthEvent:
		// c.gc.authEvent <- ev.AuthEvent.Response
	}
}

// func TestFoo(t *testing.T) {
// 	mockClient := newDefaultMockClient()
// 	convHandler := &gdmConvHandler{}
// 	appState := UIModel{
// 		PamMTx:     pam_test.NewModuleTransactionDummy(convHandler),
// 		Client:     mockClient,
// 		ClientType: Gdm,
// 	}

// 	teaOpts := []tea.ProgramOption{tea.WithInput(nil), tea.WithoutRenderer()}
// 	p := tea.NewProgram(&appState, teaOpts...)
// 	go func() {
// 		p.Send(userSelected{username: "Test user"})
// 	}()
// 	if _, err := p.Run(); err != nil {
// 		t.Fatalf("Cancelled authentication: %v", err)
// 	}

// 	fmt.Printf("Module done, exit status is %#v\n", appState.ExitStatus())
// }

func TestGdmModel(t *testing.T) {
	// t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	earlyStopMsg := pamError{
		status: pam.ErrSystem,
		msg:    "model did not return anything",
	}

	testCases := map[string]struct {
		client           authd.PAMClient
		supportedLayouts []*authd.UILayout
		messages         []tea.Msg

		wantExitStatus PamReturnStatus
		wantRequests   []gdm.RequestType
		wantStage      pam_proto.Stage
		wantBrokers    []*authd.ABResponse_BrokerInfo
	}{
		// "Other stuff...": {
		// 	// client:       &mockClient{},
		// 	supportedLayouts: []*authd.UILayout{},
		// 	wantRequests:     []gdm.RequestType{gdm.RequestType_uiLayoutCapabilities},
		// 	wantExitStatus: pamError{
		// 		status: pam.ErrCredUnavail,
		// 		msg:    "UI does not support any layouts",
		// 	},
		// },

		"User selection stage": {
			// client:           ,
			wantBrokers:    newDefaultMockClient().availableBrokersRet,
			wantRequests:   []gdm.RequestType{gdm.RequestType_uiLayoutCapabilities},
			wantStage:      pam_proto.Stage_userSelection,
			wantExitStatus: earlyStopMsg,
		},

		"Broker selection stage": {
			// client:           ,
			wantBrokers: newDefaultMockClient().availableBrokersRet,
			messages:    []tea.Msg{userSelected{username: "test_username"}},
			wantRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
				gdm.RequestType_changeStage,
			},
			wantStage:      pam_proto.Stage_brokerSelection,
			wantExitStatus: earlyStopMsg,
		},

		// Error cases
		"Error on no UI layouts": {
			client:           &mockClient{},
			supportedLayouts: []*authd.UILayout{},
			wantRequests:     []gdm.RequestType{gdm.RequestType_uiLayoutCapabilities},
			wantExitStatus: pamError{
				status: pam.ErrCredUnavail,
				msg:    "UI does not support any layouts",
			},
		},
		"Early stop": {
			client:         &mockClient{},
			messages:       []tea.Msg{tea.Quit},
			wantRequests:   []gdm.RequestType{gdm.RequestType_uiLayoutCapabilities},
			wantExitStatus: earlyStopMsg,
		},
	}
	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			// t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			gdmHandler := &gdmConvHandler{}
			appState := UIModel{
				PamMTx:     pam_test.NewModuleTransactionDummy(gdmHandler),
				ClientType: Gdm,
				Client:     tc.client,
			}

			if tc.client == nil {
				appState.Client = newDefaultMockClient()
			}
			if tc.supportedLayouts == nil {
				required, _ := "required", "optional"
				supportedEntries := "optional:chars,chars_password"
				// requiredWithBooleans := "required:true,false"
				optionalWithBooleans := "optional:true,false"
				gdmHandler.supportedLayouts = []*authd.UILayout{
					{
						Type:  "form",
						Label: &required,
						Entry: &supportedEntries,
						Wait:  &optionalWithBooleans,
						// Button: &optional,
					},
				}
			}

			teaOpts := []tea.ProgramOption{tea.WithInput(nil), tea.WithoutRenderer()}
			p := tea.NewProgram(&appState, teaOpts...)
			go func() {
				// p.Send(userSelected{username: "Test user"})
				// p.Send(appState.quit())
				// FIXME: override update and wait for all the events we should
				// emit have been processed... Then, die.
				for _, m := range tc.messages {
					p.Send(m)
				}
				time.Sleep(time.Millisecond * 500)
				p.Quit()
			}()
			_, err := p.Run()
			require.NoError(t, err)

			require.Equal(t, tc.wantExitStatus, appState.exitStatus)
			require.Equal(t, tc.wantRequests, gdmHandler.receivedRequests)
			require.Equal(t, tc.wantStage, gdmHandler.currentStage)
			requireEqualData(t, tc.wantBrokers, gdmHandler.receivedBrokers)
		})
	}
}
