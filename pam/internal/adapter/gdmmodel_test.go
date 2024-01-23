package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"
	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/brokers/responses"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/gdm"
	"github.com/ubuntu/authd/pam/internal/pam_test"
	pam_proto "github.com/ubuntu/authd/pam/internal/proto"
	"google.golang.org/grpc"
)

var privateKey *rsa.PrivateKey

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

	selectBrokerRet *authd.SBResponse
	selectBrokerErr error

	getAuthenticationModesErr error
	getAuthenticationModesRet []*authd.GAMResponse_AuthenticationMode

	selectAuthenticationModeRet *authd.UILayout
	selectAuthenticationModeErr error

	isAuthenticatedRet           *authd.IAResponse
	isAuthenticatedWantChallenge string
	isAuthenticatedErr           error

	endSessionErr              error
	setDefaultBrokerForUserErr error
}

func newDefaultMockClient() *mockClient {
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
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
		selectBrokerRet: &authd.SBResponse{
			SessionId:     uuid.New().String(),
			EncryptionKey: base64.StdEncoding.EncodeToString(pubASN1),
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
	foundBroker := false
	for _, b := range mc.availableBrokersRet {
		if in.BrokerId == b.Id {
			foundBroker = true
			break
		}
	}
	if !foundBroker {
		return nil, fmt.Errorf("broker '%s' not found", in.BrokerId)
	}
	fmt.Println("We're at SelectBroker")
	if mc.selectBrokerErr != nil {
		return nil, mc.selectBrokerErr
	}
	return mc.selectBrokerRet, nil
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

	if mc.selectAuthenticationModeRet == nil {
		return &authd.SAMResponse{}, nil
	}

	for _, mode := range mc.getAuthenticationModesRet {
		if mode.Id == in.AuthenticationModeId {
			return &authd.SAMResponse{
				UiLayoutInfo: mc.selectAuthenticationModeRet,
			}, nil
		}
	}
	return &authd.SAMResponse{}, nil
}

// IsAuthenticated simulates IsAuthenticated through gdm protocol.
func (mc *mockClient) IsAuthenticated(ctx context.Context, in *authd.IARequest, opts ...grpc.CallOption) (
	*authd.IAResponse, error) {
	fmt.Println("We're at IsAuthenticated")
	if mc.isAuthenticatedErr != nil {
		return nil, mc.isAuthenticatedErr
	}
	if mc.isAuthenticatedRet != nil {
		return mc.isAuthenticatedRet, nil
	}
	if mc.isAuthenticatedWantChallenge == "" {
		return nil, errors.New("no wanted challenge provided")
	}

	challenge := in.AuthenticationData.GetChallenge()
	if challenge == "" {
		return nil, errors.New("no challenge provided")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return nil, err
	}
	plaintext, err := rsa.DecryptOAEP(sha512.New(), nil, privateKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	if string(plaintext) != mc.isAuthenticatedWantChallenge {
		return &authd.IAResponse{
			Access: responses.AuthRetry,
		}, nil
	}

	return &authd.IAResponse{
		Access: responses.AuthGranted,
	}, nil
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
	mu sync.Mutex

	receivedRequests     []gdm.RequestType
	supportedLayouts     []*authd.UILayout
	receivedEventsTypes  []gdm.EventType
	receivedEvents       []gdm.Event
	eventsReceived       chan struct{}
	pendingEvents        []*gdm.EventData
	pendingEventsFlushed chan struct{}

	currentStage     pam_proto.Stage
	receivedBrokers  []*authd.ABResponse_BrokerInfo
	selectedBrokerID string
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
		json, err := d.JSON()
		if err != nil {
			return nil, err
		}
		if string(json) != `{"type":"poll"}` {
			fmt.Println("->", string(json))
		}
		ret, err := h.handleGdmData(d)
		if err != nil {
			return nil, err
		}
		json, err = ret.JSON()
		if err != nil {
			return nil, err
		}
		if string(json) != `{"type":"pollResponse"}` {
			fmt.Println("<-", string(json))
		}
		return ret, nil
	}).RespondPAMBinary(ptr)
	// json, err := gdm.DecodeJSONProtoMessage(ptr)
	// if err != nil {
	// 	return nil, err
	// }
	// d, err := gdm.NewDataFromJSON(json)
	// if err != nil {
	// 	return nil, err
	// }
	// json, _ = d.JSON()
	// if string(json) != `{"type":"poll"}` {
	// 	fmt.Println("->", string(json))
	// }
	// ret, err := h.handleGdmData(d)
	// if err != nil {
	// 	return nil, err
	// }
	// json, _ = ret.JSON()
	// if err != nil {
	// 	return nil, err
	// }
	// if string(json) != `{"type":"pollResponse"}` {
	// 	fmt.Println("<-", string(json))
	// }
	// msg, err := gdm.NewJSONProtoMessage(json)
	// if err != nil {
	// 	return nil, err
	// }
	// return pam.BinaryPointer(msg), nil
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
		h.mu.Lock()
		events := h.pendingEvents
		h.pendingEvents = nil
		h.mu.Unlock()
		if events != nil {
			defer close(h.pendingEventsFlushed)
		}
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
	h.mu.Lock()
	h.receivedRequests = append(h.receivedRequests, gdmData.Request.Type)
	h.mu.Unlock()

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
		h.mu.Lock()
		h.currentStage = req.ChangeStage.Stage
		h.mu.Unlock()

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
	switch ev := event.Data.(type) {
	case *gdm.EventData_BrokersReceived:
		h.mu.Lock()
		h.receivedBrokers = ev.BrokersReceived.BrokersInfos
		h.mu.Unlock()
		// c.gc.brokersInfos = ev.BrokersReceived.BrokersInfos
		// c.gc.gotBrokersInfos <- struct{}{}

	case *gdm.EventData_BrokerSelected:
		h.mu.Lock()
		h.selectedBrokerID = ev.BrokerSelected.BrokerId
		h.mu.Unlock()
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

	h.mu.Lock()
	h.receivedEventsTypes = append(h.receivedEventsTypes, event.Type)
	h.receivedEvents = append(h.receivedEvents, event.Data)
	h.mu.Unlock()

	h.eventsReceived <- struct{}{}
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

type mockUIModel struct {
	UIModel

	gdmHandler *gdmConvHandler

	wantMessages        []tea.Msg
	wantMessagesHandled chan struct{}
}

type appendGdmEvent struct {
	event *gdm.EventData
}

func (m *mockUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	_, cmd := m.UIModel.Update(msg)

	switch msg := msg.(type) {
	case appendGdmEvent:
		m.gdmHandler.mu.Lock()
		defer m.gdmHandler.mu.Unlock()
		if m.gdmHandler.pendingEvents == nil {
			m.gdmHandler.pendingEventsFlushed = make(chan struct{})
		}
		m.gdmHandler.pendingEvents = append(m.gdmHandler.pendingEvents, msg.event)
	}

	for i, v := range m.wantMessages {
		fmt.Printf("Comparing %#v with %#v\n", v, msg)
		if reflect.DeepEqual(v, msg) {
			// if v == msg {
			fmt.Printf("Before %#v len %d", m.wantMessages, len(m.wantMessages))
			m.wantMessages = slices.Delete(m.wantMessages, i, i+1)
			fmt.Printf("THEY MATCH, want msg now is %#v (len %d)\n", m.wantMessages,
				len(m.wantMessages))

			if len(m.wantMessages) == 0 {
				close(m.wantMessagesHandled)
			}
			break
		}
	}

	return m, cmd
}

// func filter(model tea.Model, msg tea.Msg) tea.Msg {
// 	// nolint:forcetypeassert // it's a programmer error if it's not
// 	m := model.(*mockUIModel)

// 	for i, v := range m.wantMessages {
// 		fmt.Printf("Comparing %#v with %#v\n", v, msg)
// 		if reflect.DeepEqual(v, msg) {
// 			fmt.Printf("THEY MATCH\n")
// 			m.wantMessages = slices.Delete(m.wantMessages, i, i+1)

// 			if len(m.wantMessages) == 0 {
// 				close(m.wantMessagesHandled)
// 			}
// 			break
// 		}
// 	}

// 	return msg
// }

func getFormUILayout() *authd.UILayout {
	required, _ := "required", "optional"
	supportedEntries := "optional:chars,chars_password"
	// requiredWithBooleans := "required:true,false"
	optionalWithBooleans := "optional:true,false"
	return &authd.UILayout{
		Type:  "form",
		Label: &required,
		Entry: &supportedEntries,
		Wait:  &optionalWithBooleans,
		// Button: &optional,
	}
}

func TestGdmModel(t *testing.T) {
	// t.Parallel()
	// t.Cleanup(pam_test.MaybeDoLeakCheck)

	earlyStopMsg := pamError{
		status: pam.ErrSystem,
		msg:    "model did not return anything",
	}

	type gdmTestWaitDone struct{}

	testCases := map[string]struct {
		client               authd.PAMClient
		supportedLayouts     []*authd.UILayout
		messages             []tea.Msg
		gdmEvents            []*gdm.EventData
		pamUser              string
		ignoreWaitController bool

		wantExitStatus     PamReturnStatus
		wantGdmRequests    []gdm.RequestType
		wantStage          pam_proto.Stage
		wantBrokers        []*authd.ABResponse_BrokerInfo
		wantSelectedBroker string
		wantUsername       string
		wantMessages       []tea.Msg
		wantGdmEvents      []gdm.EventType
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
			wantBrokers:     newDefaultMockClient().availableBrokersRet,
			wantGdmRequests: []gdm.RequestType{gdm.RequestType_uiLayoutCapabilities},
			wantStage:       pam_proto.Stage_userSelection,
			wantExitStatus:  earlyStopMsg,
		},
		"Broker selection stage caused by server-side user selection": {
			messages:     []tea.Msg{userSelected{username: "daemon-selected-user"}},
			wantUsername: "daemon-selected-user",
			wantBrokers:  newDefaultMockClient().availableBrokersRet,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage:      pam_proto.Stage_brokerSelection,
			wantExitStatus: earlyStopMsg,
		},
		"Broker selection stage caused by server-side user selection after broker": {
			messages: []tea.Msg{
				tea.Tick(300*time.Millisecond, func(t time.Time) tea.Msg {
					return userSelected{username: "daemon-selected-user"}
				})(),
			},
			wantUsername: "daemon-selected-user",
			wantBrokers:  newDefaultMockClient().availableBrokersRet,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage:      pam_proto.Stage_brokerSelection,
			wantExitStatus: earlyStopMsg,
		},
		"Broker selection stage caused by client-side user selection": {
			gdmEvents: []*gdm.EventData{
				{
					Type: gdm.EventType_userSelected,
					Data: &gdm.EventData_UserSelected{
						UserSelected: &gdm.Events_UserSelected{UserId: "gdm-selected-user"},
					},
				},
			},
			wantUsername: "gdm-selected-user",
			wantBrokers:  newDefaultMockClient().availableBrokersRet,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage:      pam_proto.Stage_brokerSelection,
			wantExitStatus: earlyStopMsg,
		},
		"Broker selection stage caused by module user selection": {
			pamUser:      "gdm-pam-selected-user",
			wantUsername: "gdm-pam-selected-user",
			wantBrokers:  newDefaultMockClient().availableBrokersRet,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage:      pam_proto.Stage_brokerSelection,
			wantExitStatus: earlyStopMsg,
		},
		"Challenge stage caused by server-side broker selection": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectAuthenticationModeRet = getFormUILayout()
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: earlyStopMsg,
		},
		// "Authenticated after server-side user, broker and authMode selection": {
		// "tmp": {
		// 	client: func() authd.PAMClient {
		// 		mockClient := newDefaultMockClient()
		// 		brokerID := mockClient.availableBrokersRet[0].Id
		// 		mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
		// 		mockClient.selectAuthenticationModeRet = getFormUILayout()
		// 		return mockClient
		// 	}(),
		// 	messages: []tea.Msg{
		// 		userSelected{username: "daemon-selected-user-and-broker"},
		// 		tea.Sequence(
		// 			tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		// 				return appendGdmEvent{
		// 					event: &gdm.EventData{
		// 						Type: gdm.EventType_isAuthenticatedRequested,
		// 						Data: &gdm.EventData_IsAuthenticatedRequested{
		// 							IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
		// 								Challenge: ptrValue("gdm-password"),
		// 							},
		// 						},
		// 					},
		// 				}
		// 			}),
		// 			sendEvent(gdmWaitDone{}),
		// 		)(),
		// 	},
		// 	wantUsername:       "daemon-selected-user-and-broker",
		// 	wantBrokers:        newDefaultMockClient().availableBrokersRet,
		// 	wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
		// 	wantMessages:       []tea.Msg{gdmWaitDone{}},
		// 	wantGdmRequests: []gdm.RequestType{
		// 		gdm.RequestType_uiLayoutCapabilities,
		// 		gdm.RequestType_changeStage,
		// 	},
		// 	wantGdmEvents: []gdm.EventType{
		// 		gdm.EventType_userSelected,
		// 		gdm.EventType_brokersReceived,
		// 		gdm.EventType_brokerSelected,
		// 		gdm.EventType_authModeSelected,
		// 	},
		// 	wantStage:      pam_proto.Stage_challenge,
		// 	wantExitStatus: earlyStopMsg,
		// },
		"AuthMode selection stage caused after server-side broker selection by client request if there is only one auth mode": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectAuthenticationModeRet = getFormUILayout()
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				tea.Sequence(
					tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
						return appendGdmEvent{
							event: &gdm.EventData{
								Type: gdm.EventType_userSelected,
								Data: &gdm.EventData_StageChanged{
									StageChanged: &gdm.Events_StageChanged{
										Stage: pam_proto.Stage_authModeSelection,
									},
								},
							},
						}
					}),
					sendEvent(gdmTestWaitDone{}),
				)(),
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantMessages: []tea.Msg{gdmTestWaitDone{}},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
			},
			wantStage:      pam_proto.Stage_authModeSelection,
			wantExitStatus: earlyStopMsg,
		},
		"AuthMode selection stage caused after server-side broker selection by client request with multiple auth modes": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getAuthenticationModesRet = []*authd.GAMResponse_AuthenticationMode{
					{
						Id:    "password",
						Label: "Password authentication",
					},
					{
						Id:    "pincode",
						Label: "Pin code",
					},
				}
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectAuthenticationModeRet = getFormUILayout()
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				tea.Sequence(
					tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
						return appendGdmEvent{
							event: &gdm.EventData{
								Type: gdm.EventType_userSelected,
								Data: &gdm.EventData_StageChanged{
									StageChanged: &gdm.Events_StageChanged{
										Stage: pam_proto.Stage_authModeSelection,
									},
								},
							},
						}
					}),
					sendEvent(gdmTestWaitDone{}),
				)(),
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantMessages: []tea.Msg{gdmTestWaitDone{}},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
			},
			wantStage:      pam_proto.Stage_authModeSelection,
			wantExitStatus: earlyStopMsg,
		},

		// Error cases
		"Error on no UI layouts": {
			client: &mockClient{
				availableBrokersRet: newDefaultMockClient().availableBrokersRet,
			},
			supportedLayouts: []*authd.UILayout{},
			wantGdmRequests:  []gdm.RequestType{gdm.RequestType_uiLayoutCapabilities},
			wantBrokers:      newDefaultMockClient().availableBrokersRet,
			wantGdmEvents:    []gdm.EventType{gdm.EventType_brokersReceived},
			wantExitStatus: pamError{
				status: pam.ErrCredUnavail,
				msg:    "UI does not support any layouts",
			},
		},
		"Error on brokers fetching error": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				mockClient.availableBrokersErr = errors.New("brokers loading failed")
				return mockClient
			}(),
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "could not get current available brokers: brokers loading failed",
			},
		},
		"Error on no brokers": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				mockClient.availableBrokersRet = nil
				return mockClient
			}(),
			wantExitStatus: pamError{
				status: pam.ErrAuthinfoUnavail,
				msg:    "No brokers available",
			},
		},
		"Error on forced quit": {
			client:               &mockClient{},
			messages:             []tea.Msg{tea.Quit()},
			ignoreWaitController: true,
			wantExitStatus:       earlyStopMsg,
		},
		"Error on invalid poll data response for missing type": {
			wantBrokers: newDefaultMockClient().availableBrokersRet,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
			},
			gdmEvents: []*gdm.EventData{
				{
					Type: gdm.EventType_userSelected,
				},
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_brokersReceived,
			},
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "Sending GDM poll failed: Conversation error\npoll response data member 0 invalid: missing event data",
			},
		},
		"Error on invalid poll data response for missing data": {
			wantBrokers: newDefaultMockClient().availableBrokersRet,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
			},
			gdmEvents: []*gdm.EventData{{}},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_brokersReceived,
			},
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "Sending GDM poll failed: Conversation error\npoll response data member 0 invalid: missing event type",
			},
		},
		"Error on invalid broker selection": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectBrokerErr = errors.New("error during broker selection")
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage: pam_proto.Stage_brokerSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "can't select broker: error during broker selection",
			},
		},
		"Error on authentication mode selection": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectAuthenticationModeErr = errors.New("error selecting auth mode")
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage: pam_proto.Stage_authModeSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "can't select authentication mode: error selecting auth mode",
			},
		},
		"Error during broker selection if session ID is empty": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectBrokerRet = &authd.SBResponse{}
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage: pam_proto.Stage_brokerSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "no session ID returned by broker",
			},
		},
		"Error during broker selection if encryption key is empty": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectBrokerRet.EncryptionKey = ""
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage: pam_proto.Stage_brokerSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "no encryption key returned by broker",
			},
		},
		"Error during broker selection if encryption key is not valid base64": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectBrokerRet.EncryptionKey = "no encryption key returned by broker"
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage: pam_proto.Stage_brokerSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "encryption key sent by broker is not a valid base64 encoded string: illegal base64 data at input byte 2",
			},
		},
		"Error during broker selection if encryption key is not valid key": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectBrokerRet.EncryptionKey = base64.StdEncoding.EncodeToString(
					[]byte("not a valid encryption key!"))
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage: pam_proto.Stage_brokerSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "<ignored>",
			},
		},
		"Error during broker auth mode selection if UI is not valid": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
			},
			wantStage: pam_proto.Stage_authModeSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "invalid empty UI Layout information from broker",
			},
		},
		"Error on invalid auth-mode layout type": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectAuthenticationModeRet = &authd.UILayout{
					Type: "invalid layout",
				}
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    `unknown layout type: "invalid layout"`,
			},
		},
		"Error on authentication client failure": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectAuthenticationModeRet = getFormUILayout()
				mockClient.isAuthenticatedErr = errors.New("some authentication error")
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				tea.Sequence(
					tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
						return appendGdmEvent{
							event: &gdm.EventData{
								Type: gdm.EventType_isAuthenticatedRequested,
								Data: &gdm.EventData_IsAuthenticatedRequested{
									IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
										Challenge: ptrValue("gdm-password"),
									},
								},
							},
						}
					}),
					sendEvent(gdmTestWaitDone{}),
				)(),
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantMessages:       []tea.Msg{gdmTestWaitDone{}},
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "authentication status failure: some authentication error",
			},
		},
		"Error on authentication client invalid message": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectAuthenticationModeRet = getFormUILayout()
				mockClient.isAuthenticatedRet = &authd.IAResponse{
					Access: responses.AuthDenied,
					Msg:    "invalid JSON",
				}
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				tea.Sequence(
					tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
						return appendGdmEvent{
							event: &gdm.EventData{
								Type: gdm.EventType_isAuthenticatedRequested,
								Data: &gdm.EventData_IsAuthenticatedRequested{
									IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
										Challenge: ptrValue("gdm-password"),
									},
								},
							},
						}
					}),
					sendEvent(gdmTestWaitDone{}),
				)(),
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantMessages:       []tea.Msg{gdmTestWaitDone{}},
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "invalid json data from provider: invalid character 'i' looking for beginning of value",
			},
		},
		"Error on authentication client denied": {
			client: func() authd.PAMClient {
				mockClient := newDefaultMockClient()
				brokerID := mockClient.availableBrokersRet[0].Id
				mockClient.getPreviousBrokerRet = authd.GPBResponse{PreviousBroker: &brokerID}
				mockClient.selectAuthenticationModeRet = getFormUILayout()
				mockClient.isAuthenticatedRet = &authd.IAResponse{
					Access: responses.AuthDenied,
					Msg:    `{"message": "you're not allowed!"}`,
				}
				return mockClient
			}(),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				tea.Sequence(
					tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
						return appendGdmEvent{
							event: &gdm.EventData{
								Type: gdm.EventType_isAuthenticatedRequested,
								Data: &gdm.EventData_IsAuthenticatedRequested{
									IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
										Challenge: ptrValue("gdm-wrong-password"),
									},
								},
							},
						}
					}),
					sendEvent(gdmTestWaitDone{}),
				)(),
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantBrokers:        newDefaultMockClient().availableBrokersRet,
			wantSelectedBroker: newDefaultMockClient().availableBrokersRet[0].Id,
			wantMessages:       []tea.Msg{gdmTestWaitDone{}},
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage,
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrAuth,
				msg:    "you're not allowed!",
			},
		},
	}
	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			// t.Parallel()
			// t.Cleanup(pam_test.MaybeDoLeakCheck)

			gdmHandler := &gdmConvHandler{
				pendingEventsFlushed: make(chan struct{}),
				eventsReceived:       make(chan struct{}),
				pendingEvents:        tc.gdmEvents,
			}
			uiModel := UIModel{
				PamMTx:     pam_test.NewModuleTransactionDummy(gdmHandler),
				ClientType: Gdm,
				Client:     tc.client,
			}
			appState := mockUIModel{
				UIModel:             uiModel,
				gdmHandler:          gdmHandler,
				wantMessages:        append(tc.messages, tc.wantMessages...),
				wantMessagesHandled: make(chan struct{}),
			}

			if tc.client == nil {
				appState.Client = newDefaultMockClient()
			}
			if tc.supportedLayouts != nil {
				gdmHandler.supportedLayouts = tc.supportedLayouts
			} else {
				gdmHandler.supportedLayouts = []*authd.UILayout{getFormUILayout()}
			}

			if tc.pamUser != "" {
				require.NoError(t, uiModel.PamMTx.SetItem(pam.User, tc.pamUser))
			}

			devNull, err := os.OpenFile("/dev/null", os.O_WRONLY|os.O_APPEND, 0600)
			require.NoError(t, err)
			teaOpts := []tea.ProgramOption{
				tea.WithInput(nil),
				tea.WithoutRenderer(),
				tea.WithoutSignals(),
				// Explicitly set the output to something so that the program
				// won't try to init some terminal fancy things that also appear
				// to be racy...
				// See: https://github.com/charmbracelet/bubbletea/issues/910
				tea.WithOutput(devNull),
			}
			p := tea.NewProgram(&appState, teaOpts...)
			controlDone := make(chan struct{})
			go func() {
				wg := sync.WaitGroup{}
				if appState.wantMessages != nil {
					for _, m := range tc.messages {
						fmt.Println("Sent message", m)
						p.Send(m)
					}
					wg.Add(1)
					go func() {
						<-appState.wantMessagesHandled
						wg.Done()
					}()
				}
				if tc.gdmEvents != nil {
					wg.Add(1)
					go func() {
						<-gdmHandler.pendingEventsFlushed
						wg.Done()
					}()
				}
				if tc.wantGdmEvents != nil {
					wg.Add(1)
					go func() {
						for {
							foundAll := true
							gdmHandler.mu.Lock()
							for _, ev := range tc.wantGdmEvents {
								if !slices.Contains(gdmHandler.receivedEventsTypes, ev) {
									foundAll = false
									break
								}
							}
							fmt.Println("Want events", tc.wantGdmEvents)
							fmt.Println("Got events", gdmHandler.receivedEventsTypes)
							gdmHandler.mu.Unlock()
							if foundAll {
								break
							}
							<-gdmHandler.eventsReceived
						}
						wg.Done()
					}()
				}

				wg.Wait()

				p.Send(tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
					defer close(controlDone)
					return tea.Quit()
				})())
			}()
			_, err = p.Run()
			require.NoError(t, err)

			if !tc.ignoreWaitController {
				select {
				case <-time.After(40 * time.Second):
					t.Fatalf("timeout waiting for controller")
				case <-controlDone:
				}
			}
			gdmHandler.mu.Lock()
			defer gdmHandler.mu.Unlock()

			if tc.wantExitStatus.Message() == "<ignored>" {
				wantErr, ok := tc.wantExitStatus.(PamReturnError)
				require.True(t, ok, "expected exit status should be an error")
				pamErr, ok := appState.ExitStatus().(PamReturnError)
				require.True(t, ok, "exit status should be an error")
				require.Equal(t, wantErr.Status(), pamErr.Status())
			} else {
				require.Equal(t, tc.wantExitStatus, appState.exitStatus)
			}
			for _, req := range tc.wantGdmRequests {
				require.Contains(t, gdmHandler.receivedRequests, req)
			}
			require.Equal(t, tc.wantStage, gdmHandler.currentStage)
			requireEqualData(t, tc.wantBrokers, gdmHandler.receivedBrokers)
			require.Equal(t, tc.wantSelectedBroker, gdmHandler.selectedBrokerID)

			username, err := appState.PamMTx.GetItem(pam.User)
			require.NoError(t, err)
			require.Equal(t, tc.wantUsername, username)
		})
	}
}

// ptrValue returns a pointer to the given value to simplify the syntax for const.
func ptrValue[T any](value T) *T {
	return &value
}

func TestMain(m *testing.M) {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	defer pam_test.MaybeDoLeakCheck()
	if err != nil {
		panic(fmt.Sprintf("could not create an valid rsa key: %v", err))
	}
	os.Exit(m.Run())
}
