package adapter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/brokers/responses"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/gdm"
	"github.com/ubuntu/authd/pam/internal/pam_test"
	"github.com/ubuntu/authd/pam/internal/proto"
	pam_proto "github.com/ubuntu/authd/pam/internal/proto"
	"golang.org/x/exp/constraints"
)

var gdmTestPrivateKey *rsa.PrivateKey
var gdmTestSequentialMessages atomic.Int64

const gdmTestIgnoredMessage string = "<ignored>"

type gdmConvHandler struct {
	mu *sync.Mutex
	t  *testing.T

	wantRequests        []gdm.RequestType
	handledRequests     []gdm.RequestType
	allRequestsReceived chan struct{}

	receivedEvents    []*gdm.EventData
	wantEvents        []gdm.EventType
	allEventsReceived chan struct{}

	pendingEvents        []*gdm.EventData
	pendingEventsFlushed chan struct{}

	supportedLayouts []*authd.UILayout
	receivedBrokers  []*authd.ABResponse_BrokerInfo
	selectedBrokerID string

	currentStageCond    sync.Cond
	currentStage        pam_proto.Stage
	stageChanges        []pam_proto.Stage
	lastNotifiedStage   *pam_proto.Stage
	currentStageChanged chan struct{}
}

func (h *gdmConvHandler) checkAllEventsHaveBeenEmitted() bool {
	receivedEventTypes := []gdm.EventType{}
	for _, e := range h.receivedEvents {
		receivedEventTypes = append(receivedEventTypes, e.Type)
	}

	return isSupersetOf(receivedEventTypes, h.wantEvents)
}

func isSupersetOf[T constraints.Ordered](a []T, b []T) bool {
	tracker := make(map[T]int)
	for _, v := range a {
		tracker[v]++
	}

	for _, value := range b {
		n, found := tracker[value]
		if !found {
			return false
		}
		if n < 1 {
			return false
		}
		tracker[value] = n - 1
	}
	return true
}

func (h *gdmConvHandler) checkAllRequestsHaveBeenHandled() bool {
	return isSupersetOf(h.handledRequests, h.wantRequests)
}

func (h *gdmConvHandler) RespondPAM(style pam.Style, prompt string) (string, error) {
	switch style {
	case pam.TextInfo:
		h.t.Logf("GDM PAM Info Message: %s\n", prompt)
	case pam.ErrorMsg:
		h.t.Logf("GDM PAM Error Message: %s\n", prompt)
	default:
		return "", fmt.Errorf("PAM style %d not implemented", style)
	}
	return "", nil
}

func (h *gdmConvHandler) RespondPAMBinary(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return gdm.DataConversationFunc(func(inData *gdm.Data) (*gdm.Data, error) {
		outData, err := h.handleGdmData(inData)
		if err != nil {
			return nil, err
		}
		if inData.Type == gdm.DataType_poll && outData.PollResponse == nil {
			return outData, err
		}
		json, err := inData.JSON()
		if err != nil {
			return nil, err
		}
		h.t.Log("->", string(json))
		json, err = outData.JSON()
		if err != nil {
			return nil, err
		}
		h.t.Log("<-", string(json))
		return outData, nil
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
		if events != nil {
			go func() {
				// Ensure we mark the events as flushed only after we've returned.
				time.Sleep(gdmPollFrequency * 2)
				h.pendingEventsFlushed <- struct{}{}
			}()
		}
		return &gdm.Data{
			Type:         gdm.DataType_pollResponse,
			PollResponse: events,
		}, nil

	case gdm.DataType_event:
		if err := h.handleEvent(gdmData.Event); err != nil {
			return nil, err
		}
		return &gdm.Data{
			Type: gdm.DataType_eventAck,
		}, nil
	}

	return nil, fmt.Errorf("unhandled protocol message %s",
		gdmData.Type.String())
}

func (h *gdmConvHandler) handleAuthDRequest(gdmData *gdm.Data) (ret *gdm.Data, err error) {
	defer func() {
		h.handledRequests = append(h.handledRequests, gdmData.Request.Type)
		if h.wantRequests == nil {
			return
		}
		if !h.checkAllRequestsHaveBeenHandled() {
			return
		}

		h.wantRequests = nil
		go func() {
			// Mark the events received after or while we're returning.
			close(h.allRequestsReceived)
		}()
	}()

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
		h.t.Logf("Switching to stage %s", req.ChangeStage.Stage)
		h.stageChanges = append(h.stageChanges, req.ChangeStage.Stage)

		h.currentStage = req.ChangeStage.Stage
		h.currentStageCond.L.Unlock()
		h.currentStageCond.Broadcast()
		h.currentStageCond.L.Lock()

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

func (h *gdmConvHandler) handleEvent(event *gdm.EventData) error {
	defer func() {
		h.receivedEvents = append(h.receivedEvents, event)

		if h.wantEvents == nil {
			return
		}
		if !h.checkAllEventsHaveBeenEmitted() {
			return
		}

		h.wantEvents = nil
		go func() {
			// Mark the events received after or while we're returning.
			close(h.allEventsReceived)
		}()
	}()

	switch ev := event.Data.(type) {
	case *gdm.EventData_BrokersReceived:
		h.receivedBrokers = ev.BrokersReceived.BrokersInfos

	case *gdm.EventData_BrokerSelected:
		h.selectedBrokerID = ev.BrokerSelected.BrokerId

	case *gdm.EventData_AuthModesReceived:
		// TODO: Check the auth modes are matching.

	case *gdm.EventData_UiLayoutReceived:
		if !slices.ContainsFunc(h.supportedLayouts, func(layout *authd.UILayout) bool {
			return layout.Type == ev.UiLayoutReceived.UiLayout.Type
		}) {
			return fmt.Errorf(`unknown layout type: "%s"`, ev.UiLayoutReceived.UiLayout.Type)
		}
	}

	return nil
}

func (h *gdmConvHandler) waitForStageChange(stage proto.Stage) func() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.currentStage == stage && (h.lastNotifiedStage == nil || *h.lastNotifiedStage != stage) {
		h.lastNotifiedStage = &stage
		return nil
	}

	return func() {
		h.currentStageCond.L.Lock()
		defer h.currentStageCond.L.Unlock()

		for {
			// We just got notified of a stage change but we should not notify all the waiting
			// waiting requests all together, each request to this function should be queued.
			// So the goroutine that won the lock is the one that will be blocked if the stage
			// matches and if it's the first one noticing such change.
			if h.currentStage == stage && (h.lastNotifiedStage == nil || *h.lastNotifiedStage != stage) {
				h.lastNotifiedStage = &stage
				return
			}

			h.currentStageCond.Wait()
		}
	}
}

func (h *gdmConvHandler) appendPollResultEvents(events ...*gdm.EventData) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pendingEvents = append(h.pendingEvents, events...)
}

// Custom messages for testing the gdm model.

type testGdmAddPollResultEvent struct {
	event *gdm.EventData
}

type testGdmWaitForStage struct {
	stage    proto.Stage
	events   []*gdm.EventData
	commands []tea.Cmd
}

type testGdmWaitForStageDone testGdmWaitForStage

type testGdmWaitForStageCommandsDone struct {
	seq int64
}

// testGdmUIModel is an override of [UIModel] used for testing the module with gdm.
type testGdmUIModel struct {
	UIModel

	mu sync.Mutex

	gdmHandler *gdmConvHandler

	wantMessages        []tea.Msg
	wantMessagesHandled chan struct{}

	program           *tea.Program
	programHasQuit    atomic.Bool
	programShouldQuit atomic.Bool
}

func (m *testGdmUIModel) maybeHandleWantMessageUnlocked(msg tea.Msg) {
	returnErrorMsg, isError := msg.(PamReturnError)

	idx := slices.IndexFunc(m.wantMessages, func(wm tea.Msg) bool {
		match := reflect.DeepEqual(wm, msg)
		if match {
			return true
		}
		if !isError {
			return false
		}
		pamErr, ok := wm.(PamReturnError)
		if !ok {
			return false
		}
		if pamErr.Message() != gdmTestIgnoredMessage {
			return false
		}
		return pamErr.Status() == returnErrorMsg.Status()
	})

	if idx < 0 {
		return
	}

	m.wantMessages = slices.Delete(m.wantMessages, idx, idx+1)
	if len(m.wantMessages) == 0 {
		close(m.wantMessagesHandled)
	}
}

func (m *testGdmUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	log.Debugf(context.TODO(), "%#v", msg)

	m.mu.Lock()
	defer m.mu.Unlock()

	commands := []tea.Cmd{}

	_, cmd := m.UIModel.Update(msg)
	commands = append(commands, cmd)

	switch msg := msg.(type) {
	case testGdmAddPollResultEvent:
		m.gdmHandler.appendPollResultEvents(msg.event)

	case testGdmWaitForStage:
		doneMsg := (*testGdmWaitForStageDone)(&msg)
		if len(doneMsg.commands) > 0 {
			seq := gdmTestSequentialMessages.Add(1)
			doneCommandsMsg := testGdmWaitForStageCommandsDone{seq: seq}
			doneMsg.commands = append(doneMsg.commands, sendEvent(doneCommandsMsg))
			m.wantMessages = append(m.wantMessages, doneCommandsMsg)
		}

		waitFunc := m.gdmHandler.waitForStageChange(msg.stage)
		if waitFunc == nil {
			commands = append(commands, sendEvent(doneMsg))
			break
		}

		m.wantMessages = append(m.wantMessages, doneMsg)

		go func() {
			log.Debugf(context.TODO(), "Waiting for stage reached: %#v\n", doneMsg)
			waitFunc()
			log.Debugf(context.TODO(), "Stage reached: %#v\n", doneMsg)

			m.program.Send(doneMsg)
		}()

	case *testGdmWaitForStageDone:
		msgCommands := tea.Sequence(msg.commands...)
		if len(msg.events) > 0 {
			m.gdmHandler.appendPollResultEvents(msg.events...)
			// If we've events as poll results, let's wait for a polling cycle to complete
			msgCommands = tea.Sequence(tea.Tick(gdmPollFrequency, func(t time.Time) tea.Msg {
				return nil
			}), msgCommands)
		}
		commands = append(commands, msgCommands)
	}

	m.maybeHandleWantMessageUnlocked(msg)
	return m, tea.Batch(commands...)
}

func (m *testGdmUIModel) filterFunc(model tea.Model, msg tea.Msg) tea.Msg {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := msg.(tea.QuitMsg); ok {
		// Quit is never sent to the Update func so we handle it earlier.
		m.maybeHandleWantMessageUnlocked(msg)
		m.programHasQuit.Store(true)
		if !m.programShouldQuit.Load() {
			return nil
		}
	}

	return msg
}

func TestGdmModel(t *testing.T) {
	t.Parallel()

	// This is not technically an error, as it means that during the tests
	// we've stopped the program with a Quit request.
	// However we do return a PAM error in such case because that's what we're
	// going to return to the PAM stack in case authentication process has not
	// been completed fully.
	earlyStopExitStatus := pamError{
		status: pam.ErrSystem,
		msg:    "model did not return anything",
	}

	passwordUILayoutID := "Password"

	firstBrokerInfo := &authd.ABResponse_BrokerInfo{
		Id:        "testBroker",
		Name:      "The best broker!",
		BrandIcon: nil,
	}
	secondBrokerInfo := &authd.ABResponse_BrokerInfo{
		Id:        "secondaryBroker",
		Name:      "A broker that works too!",
		BrandIcon: nil,
	}
	singleBrokerClientOptions := []pam_test.DummyClientOptions{
		pam_test.WithAvailableBrokers([]*authd.ABResponse_BrokerInfo{
			firstBrokerInfo,
		}, nil),
		pam_test.WithUILayout(passwordUILayoutID, "Password authentication", pam_test.FormUILayout()),
	}
	multiBrokerClientOptions := append(slices.Clone(singleBrokerClientOptions),
		pam_test.WithAvailableBrokers([]*authd.ABResponse_BrokerInfo{
			firstBrokerInfo, secondBrokerInfo,
		}, nil),
	)

	testCases := map[string]struct {
		client           authd.PAMClient
		clientOptions    []pam_test.DummyClientOptions
		supportedLayouts []*authd.UILayout
		messages         []tea.Msg
		commands         []tea.Cmd
		gdmEvents        []*gdm.EventData
		pamUser          string

		wantExitStatus     PamReturnStatus
		wantGdmRequests    []gdm.RequestType
		wantGdmEvents      []gdm.EventType
		wantNoGdmRequests  []gdm.RequestType
		wantNoGdmEvents    []gdm.EventType
		wantBrokers        []*authd.ABResponse_BrokerInfo
		wantSelectedBroker string
		wantStage          pam_proto.Stage
		wantUsername       string
		wantMessages       []tea.Msg
	}{
		"User selection stage": {
			wantGdmRequests: []gdm.RequestType{gdm.RequestType_uiLayoutCapabilities},
			wantStage:       pam_proto.Stage_userSelection,
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_brokersReceived,
			},
			wantNoGdmRequests: []gdm.RequestType{
				gdm.RequestType_changeStage, // -> broker Selection
			},
			wantExitStatus: earlyStopExitStatus,
		},
		"Broker selection stage caused by server-side user selection": {
			messages:     []tea.Msg{userSelected{username: "daemon-selected-user"}},
			wantUsername: "daemon-selected-user",
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage:      pam_proto.Stage_brokerSelection,
			wantExitStatus: earlyStopExitStatus,
		},
		"Broker selection stage caused by server-side user selection after broker": {
			messages: []tea.Msg{
				testGdmWaitForStage{
					stage: pam_proto.Stage_userSelection,
					commands: []tea.Cmd{
						tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg {
							return userSelected{username: "daemon-selected-user"}
						}),
						sendEvent(testGdmWaitForStage{stage: pam_proto.Stage_brokerSelection}),
					},
				},
			},
			wantUsername: "daemon-selected-user",
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage:      pam_proto.Stage_brokerSelection,
			wantExitStatus: earlyStopExitStatus,
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
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage:      pam_proto.Stage_brokerSelection,
			wantExitStatus: earlyStopExitStatus,
		},
		"Broker selection stage caused by module user selection": {
			pamUser:      "gdm-pam-selected-user",
			wantUsername: "gdm-pam-selected-user",
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage:      pam_proto.Stage_brokerSelection,
			wantExitStatus: earlyStopExitStatus,
		},
		"Challenge stage caused by server-side broker and authMode selection": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil)),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{stage: pam_proto.Stage_challenge},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModesReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
			},
			wantNoGdmEvents: []gdm.EventType{
				gdm.EventType_authEvent,
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: earlyStopExitStatus,
		},
		"Challenge stage caused by client-side broker and authMode selection": {
			gdmEvents: []*gdm.EventData{
				{
					Type: gdm.EventType_userSelected,
					Data: &gdm.EventData_UserSelected{
						UserSelected: &gdm.Events_UserSelected{UserId: "gdm-selected-user-and-broker"},
					},
				},
			},
			messages: []tea.Msg{
				testGdmWaitForStage{
					stage: pam_proto.Stage_brokerSelection,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_brokerSelected,
							Data: &gdm.EventData_BrokerSelected{
								BrokerSelected: &gdm.Events_BrokerSelected{
									BrokerId: firstBrokerInfo.Id,
								},
							},
						},
					},
				},
				testGdmWaitForStage{stage: pam_proto.Stage_challenge},
			},
			wantUsername:       "gdm-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModesReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
			},
			wantNoGdmEvents: []gdm.EventType{
				gdm.EventType_authEvent,
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: earlyStopExitStatus,
		},
		"Authenticated after server-side user, broker and authMode selection": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithIsAuthenticatedWantChallenge("gdm-good-password")),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "gdm-good-password",
										},
									},
								},
							},
						},
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent,
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: PamSuccess{BrokerID: firstBrokerInfo.Id},
		},
		"Authenticated with message after server-side user, broker and authMode selection": {
			clientOptions: append(slices.Clone(multiBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithIsAuthenticatedReturn(&authd.IAResponse{
					Access: responses.AuthGranted,
					Msg:    `{"message": "Hi GDM, it's a pleasure to get you in!"}`,
				}, nil),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "gdm-good-password",
										},
									},
								},
							},
						},
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: PamSuccess{
				BrokerID: firstBrokerInfo.Id,
				// FIXME: Message is not sent in success case but it probably should!
				// msg: "Hi GDM, it's a pleasure to get you in!",
			},
		},
		"Cancelled after server-side user, broker and authMode selection": {
			clientOptions: append(slices.Clone(multiBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithIsAuthenticatedReturn(&authd.IAResponse{
					Access: responses.AuthCancelled,
				}, nil),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "any-password",
										},
									},
								},
							},
						},
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: earlyStopExitStatus,
		},
		"Authenticated after server-side user, broker and authMode selection and after various retries": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithIsAuthenticatedWantChallenge("gdm-good-password"),
				pam_test.WithIsAuthenticatedMaxRetries(1),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "gdm-bad-password",
										},
									},
								},
							},
						},
					},
					commands: []tea.Cmd{
						tea.Tick(gdmPollFrequency*2, func(t time.Time) tea.Msg {
							return testGdmAddPollResultEvent{
								event: &gdm.EventData{
									Type: gdm.EventType_isAuthenticatedRequested,
									Data: &gdm.EventData_IsAuthenticatedRequested{
										IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
											AuthenticationData: &authd.IARequest_AuthenticationData{
												Item: &authd.IARequest_AuthenticationData_Challenge{
													Challenge: "gdm-good-password",
												},
											},
										},
									},
								},
							}
						}),
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent, // retry
				gdm.EventType_authEvent, // denied
			},
			wantMessages: []tea.Msg{
				startAuthentication{},
				startAuthentication{},
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: PamSuccess{BrokerID: firstBrokerInfo.Id},
		},
		"Authenticated after client-side user, broker and authMode selection": {
			clientOptions: append(slices.Clone(multiBrokerClientOptions),
				pam_test.WithIsAuthenticatedWantChallenge("gdm-good-password"),
			),
			gdmEvents: []*gdm.EventData{
				{
					Type: gdm.EventType_userSelected,
					Data: &gdm.EventData_UserSelected{
						UserSelected: &gdm.Events_UserSelected{UserId: "gdm-selected-user-broker-and-auth-mode"},
					},
				},
			},
			messages: []tea.Msg{
				testGdmWaitForStage{
					stage: pam_proto.Stage_brokerSelection,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_brokerSelected,
							Data: &gdm.EventData_BrokerSelected{
								BrokerSelected: &gdm.Events_BrokerSelected{
									BrokerId: secondBrokerInfo.Id,
								},
							},
						},
					},
					commands: []tea.Cmd{
						sendEvent(testGdmWaitForStage{
							stage: pam_proto.Stage_challenge,
							events: []*gdm.EventData{
								{
									Type: gdm.EventType_isAuthenticatedRequested,
									Data: &gdm.EventData_IsAuthenticatedRequested{
										IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
											AuthenticationData: &authd.IARequest_AuthenticationData{
												Item: &authd.IARequest_AuthenticationData_Challenge{
													Challenge: "gdm-good-password",
												},
											},
										},
									},
								},
							},
						}),
					},
				},
			},
			wantUsername:       "gdm-selected-user-broker-and-auth-mode",
			wantSelectedBroker: secondBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent,
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: PamSuccess{BrokerID: secondBrokerInfo.Id},
		},
		"Authenticated after client-side user, broker and authMode selection and after various retries": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithIsAuthenticatedWantChallenge("gdm-good-password"),
				pam_test.WithIsAuthenticatedMaxRetries(1),
			),
			gdmEvents: []*gdm.EventData{
				{
					Type: gdm.EventType_userSelected,
					Data: &gdm.EventData_UserSelected{
						UserSelected: &gdm.Events_UserSelected{UserId: "gdm-selected-user-broker-and-auth-mode"},
					},
				},
			},
			messages: []tea.Msg{
				testGdmWaitForStage{
					stage: pam_proto.Stage_brokerSelection,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_brokerSelected,
							Data: &gdm.EventData_BrokerSelected{
								BrokerSelected: &gdm.Events_BrokerSelected{
									BrokerId: firstBrokerInfo.Id,
								},
							},
						},
					},
				},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "gdm-bad-password",
										},
									},
								},
							},
						},
					},
					commands: []tea.Cmd{
						tea.Tick(gdmPollFrequency*2, func(t time.Time) tea.Msg {
							return testGdmAddPollResultEvent{
								event: &gdm.EventData{
									Type: gdm.EventType_isAuthenticatedRequested,
									Data: &gdm.EventData_IsAuthenticatedRequested{
										IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
											AuthenticationData: &authd.IARequest_AuthenticationData{
												Item: &authd.IARequest_AuthenticationData_Challenge{
													Challenge: "gdm-good-password",
												},
											},
										},
									},
								},
							}
						}),
					},
				},
			},
			wantUsername:       "gdm-selected-user-broker-and-auth-mode",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent,
				gdm.EventType_authEvent,
			},
			wantMessages: []tea.Msg{
				startAuthentication{},
				startAuthentication{},
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: PamSuccess{BrokerID: firstBrokerInfo.Id},
		},
		"AuthMode selection stage from client after server-side broker and auth mode selection if there is only one auth mode": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_stageChanged,
							Data: &gdm.EventData_StageChanged{
								StageChanged: &gdm.Events_StageChanged{
									Stage: pam_proto.Stage_authModeSelection,
								},
							},
						},
					},
					commands: []tea.Cmd{
						sendEvent(testGdmWaitForStage{stage: pam_proto.Stage_authModeSelection}),
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
				gdm.RequestType_changeStage, // -> authMode Selection
			},
			wantMessages: []tea.Msg{
				startAuthentication{},
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
			},
			wantNoGdmEvents: []gdm.EventType{
				gdm.EventType_authEvent,
			},
			wantStage:      pam_proto.Stage_authModeSelection,
			wantExitStatus: earlyStopExitStatus,
		},
		"AuthMode selection stage from client after server-side broker and auth mode selection with multiple auth modes": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithUILayout("pincode", "Pin Code", pam_test.FormUILayout()),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_stageChanged,
							Data: &gdm.EventData_StageChanged{
								StageChanged: &gdm.Events_StageChanged{
									Stage: pam_proto.Stage_authModeSelection,
								},
							},
						},
					},
					commands: []tea.Cmd{
						sendEvent(testGdmWaitForStage{stage: pam_proto.Stage_authModeSelection}),
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
				gdm.RequestType_changeStage, // -> authMode Selection
			},
			// wantMessages: []tea.Msg{gdmTestWaitCompletion{}},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModesReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
			},
			wantStage:      pam_proto.Stage_authModeSelection,
			wantExitStatus: earlyStopExitStatus,
		},
		"AuthMode selection stage from client after client-side broker and auth mode selection if there is only one auth mode": {
			gdmEvents: []*gdm.EventData{
				{
					Type: gdm.EventType_userSelected,
					Data: &gdm.EventData_UserSelected{
						UserSelected: &gdm.Events_UserSelected{UserId: "gdm-selected-user-broker-and-auth-mode"},
					},
				},
			},
			messages: []tea.Msg{
				testGdmWaitForStage{
					stage: pam_proto.Stage_brokerSelection,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_brokerSelected,
							Data: &gdm.EventData_BrokerSelected{
								BrokerSelected: &gdm.Events_BrokerSelected{
									BrokerId: firstBrokerInfo.Id,
								},
							},
						},
					},
				},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_stageChanged,
							Data: &gdm.EventData_StageChanged{
								StageChanged: &gdm.Events_StageChanged{
									Stage: pam_proto.Stage_authModeSelection,
								},
							},
						},
					},
					commands: []tea.Cmd{
						sendEvent(testGdmWaitForStage{stage: pam_proto.Stage_authModeSelection}),
					},
				},
			},
			wantUsername:       "gdm-selected-user-broker-and-auth-mode",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
				gdm.RequestType_changeStage, // -> authMode Selection
			},
			wantMessages: []tea.Msg{
				startAuthentication{},
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
			},
			wantNoGdmEvents: []gdm.EventType{
				gdm.EventType_authEvent,
			},
			wantStage:      pam_proto.Stage_authModeSelection,
			wantExitStatus: earlyStopExitStatus,
		},
		"Authenticated after auth selection stage from client after client-side broker and auth mode selection if there is only one auth mode": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithIsAuthenticatedWantChallenge("gdm-good-password"),
			),
			gdmEvents: []*gdm.EventData{
				{
					Type: gdm.EventType_userSelected,
					Data: &gdm.EventData_UserSelected{
						UserSelected: &gdm.Events_UserSelected{UserId: "gdm-selected-user-broker-and-auth-mode"},
					},
				},
			},
			messages: []tea.Msg{
				testGdmWaitForStage{
					stage: pam_proto.Stage_brokerSelection,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_brokerSelected,
							Data: &gdm.EventData_BrokerSelected{
								BrokerSelected: &gdm.Events_BrokerSelected{
									BrokerId: firstBrokerInfo.Id,
								},
							},
						},
					},
				},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_stageChanged,
							Data: &gdm.EventData_StageChanged{
								StageChanged: &gdm.Events_StageChanged{
									Stage: pam_proto.Stage_authModeSelection,
								},
							},
						},
					},
					commands: []tea.Cmd{
						sendEvent(testGdmWaitForStage{
							stage: pam_proto.Stage_authModeSelection,
							events: []*gdm.EventData{
								{
									Type: gdm.EventType_authModeSelected,
									Data: &gdm.EventData_AuthModeSelected{
										AuthModeSelected: &gdm.Events_AuthModeSelected{
											AuthModeId: passwordUILayoutID,
										},
									},
								},
							},
							commands: []tea.Cmd{
								sendEvent(testGdmWaitForStage{
									stage: pam_proto.Stage_challenge,
									events: []*gdm.EventData{
										{
											Type: gdm.EventType_isAuthenticatedRequested,
											Data: &gdm.EventData_IsAuthenticatedRequested{
												IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
													AuthenticationData: &authd.IARequest_AuthenticationData{
														Item: &authd.IARequest_AuthenticationData_Challenge{
															Challenge: "gdm-good-password",
														},
													},
												},
											},
										},
									},
								}),
							},
						}),
					},
				},
			},
			wantUsername:       "gdm-selected-user-broker-and-auth-mode",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantMessages: []tea.Msg{
				startAuthentication{},
				startAuthentication{},
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent,
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: PamSuccess{BrokerID: firstBrokerInfo.Id},
		},
		"Authenticated after auth selection stage from client after client-side broker and auth mode selection with multiple auth modes": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithUILayout("pincode", "Write the pin Code", pam_test.FormUILayout()),
				pam_test.WithIsAuthenticatedWantChallenge("1234"),
			),
			gdmEvents: []*gdm.EventData{
				{
					Type: gdm.EventType_userSelected,
					Data: &gdm.EventData_UserSelected{
						UserSelected: &gdm.Events_UserSelected{UserId: "gdm-selected-user-broker-and-auth-mode"},
					},
				},
			},
			messages: []tea.Msg{
				testGdmWaitForStage{
					stage: pam_proto.Stage_brokerSelection,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_brokerSelected,
							Data: &gdm.EventData_BrokerSelected{
								BrokerSelected: &gdm.Events_BrokerSelected{
									BrokerId: firstBrokerInfo.Id,
								},
							},
						},
					},
				},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_stageChanged,
							Data: &gdm.EventData_StageChanged{
								StageChanged: &gdm.Events_StageChanged{
									Stage: pam_proto.Stage_authModeSelection,
								},
							},
						},
					},
					commands: []tea.Cmd{
						sendEvent(testGdmWaitForStage{
							stage: pam_proto.Stage_authModeSelection,
							events: []*gdm.EventData{
								{
									Type: gdm.EventType_authModeSelected,
									Data: &gdm.EventData_AuthModeSelected{
										AuthModeSelected: &gdm.Events_AuthModeSelected{
											AuthModeId: "pincode",
										},
									},
								},
							},
							commands: []tea.Cmd{
								sendEvent(testGdmWaitForStage{
									stage: pam_proto.Stage_challenge,
									events: []*gdm.EventData{
										{
											Type: gdm.EventType_isAuthenticatedRequested,
											Data: &gdm.EventData_IsAuthenticatedRequested{
												IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
													AuthenticationData: &authd.IARequest_AuthenticationData{
														Item: &authd.IARequest_AuthenticationData_Challenge{
															Challenge: "1234",
														},
													},
												},
											},
										},
									},
								}),
							},
						}),
					},
				},
			},
			wantUsername:       "gdm-selected-user-broker-and-auth-mode",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantMessages: []tea.Msg{
				startAuthentication{},
				startAuthentication{},
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent,
			},
			wantStage:      pam_proto.Stage_challenge,
			wantExitStatus: PamSuccess{BrokerID: firstBrokerInfo.Id},
		},

		// Error cases
		"Error on no UI layouts": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithUILayout(passwordUILayoutID, "", &authd.UILayout{}),
			),
			supportedLayouts: []*authd.UILayout{},
			wantGdmRequests:  []gdm.RequestType{gdm.RequestType_uiLayoutCapabilities},
			wantGdmEvents:    []gdm.EventType{gdm.EventType_brokersReceived},
			wantNoGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
			},
			wantExitStatus: pamError{
				status: pam.ErrCredUnavail,
				msg:    "UI does not support any layouts",
			},
		},
		"Error on brokers fetching error": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithAvailableBrokers(nil, errors.New("brokers loading failed")),
			),
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
			},
			wantNoGdmEvents: []gdm.EventType{
				gdm.EventType_brokersReceived,
				gdm.EventType_userSelected,
			},
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "could not get current available brokers: brokers loading failed",
			},
		},
		"Error on forced quit": {
			messages:       []tea.Msg{tea.Quit()},
			wantExitStatus: earlyStopExitStatus,
			wantNoGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
			},
		},
		"Error on invalid poll data response for missing type": {
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
			wantNoGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
			},
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "Sending GDM poll failed: Conversation error: poll response data member 0 invalid: missing event data",
			},
		},
		"Error on invalid poll data response for missing data": {
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
			},
			gdmEvents: []*gdm.EventData{{}},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_brokersReceived,
			},
			wantNoGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
			},
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "Sending GDM poll failed: Conversation error: poll response data member 0 invalid: missing event type",
			},
		},
		"Error on invalid broker selection": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithSelectBrokerReturn(nil, errors.New("error during broker selection")),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{stage: proto.Stage_brokerSelection},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
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
		"Error during broker selection if session ID is empty": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithSelectBrokerReturn(&authd.SBResponse{}, nil),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
			},
			wantStage: pam_proto.Stage_brokerSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "no session ID returned by broker",
			},
		},
		"Error during broker selection if encryption key is empty": {
			client: pam_test.NewDummyClient(nil, append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithSelectBrokerReturn(&authd.SBResponse{SessionId: "session-id"}, nil),
			)...),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{stage: pam_proto.Stage_brokerSelection},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
			},
			wantStage: pam_proto.Stage_brokerSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "no encryption key returned by broker",
			},
		},
		"Error during broker selection if encryption key is not valid base64": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithSelectBrokerReturn(&authd.SBResponse{
					SessionId:     "session-id",
					EncryptionKey: "no encryption key returned by broker",
				}, nil),
			),
			messages: []tea.Msg{
				tea.Sequence(tea.Tick(gdmPollFrequency, func(t time.Time) tea.Msg {
					return userSelected{username: "daemon-selected-user-and-broker"}
				}))(),
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
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
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithSelectBrokerReturn(&authd.SBResponse{
					SessionId: "session-id",
					EncryptionKey: base64.StdEncoding.EncodeToString(
						[]byte("not a valid encryption key!")),
				}, nil),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{stage: proto.Stage_brokerSelection},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
			},
			wantStage: pam_proto.Stage_brokerSelection,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    gdmTestIgnoredMessage,
			},
		},
		"Error during broker auth mode selection if UI is not valid": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithUILayout(passwordUILayoutID, "", nil),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{stage: proto.Stage_authModeSelection},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
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
		"Error on missing authentication modes": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithGetAuthenticationModesReturn([]*authd.GAMResponse_AuthenticationMode{}, nil),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{stage: proto.Stage_authModeSelection},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
			},
			wantStage: pam_proto.Stage_authModeSelection,
			wantExitStatus: pamError{
				status: pam.ErrCredUnavail,
				msg:    "no supported authentication mode available for this provider",
			},
		},
		"Error on authentication mode selection": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithSelectAuthenticationModeReturn(nil, errors.New("error selecting auth mode")),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{stage: proto.Stage_authModeSelection},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
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
		"Error on invalid auth-mode layout type": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithSelectAuthenticationModeReturn(&authd.UILayout{
					Type: "invalid layout",
				}, nil),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{stage: pam_proto.Stage_challenge},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModesReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    `Sending GDM event failed: Conversation error: unknown layout type: "invalid layout"`,
			},
		},
		"Error on authentication client failure": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithIsAuthenticatedReturn(nil, errors.New("some authentication error")),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "gdm-password",
										},
									},
								},
							},
						},
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModesReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "authentication status failure: some authentication error",
			},
		},
		"Error on authentication client invalid message": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithIsAuthenticatedReturn(&authd.IAResponse{
					Access: responses.AuthDenied,
					Msg:    "invalid JSON",
				}, nil),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "gdm-password",
										},
									},
								},
							},
						},
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModesReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrSystem,
				msg:    "invalid json data from provider: invalid character 'i' looking for beginning of value",
			},
		},
		"Error on authentication client denied because of wrong password, with error message": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithIsAuthenticatedWantChallenge("gdm-good-password"),
				pam_test.WithIsAuthenticatedMessage("you're not allowed!"),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker-with-wrong-pass"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "gdm-wrong-password",
										},
									},
								},
							},
						},
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker-with-wrong-pass",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModesReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrAuth,
				msg:    "you're not allowed!",
			},
		},
		"Error on authentication client denied because of wrong password": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithIsAuthenticatedWantChallenge("gdm-good-password"),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker-with-wrong-pass"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "gdm-wrong-password",
										},
									},
								},
							},
						},
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker-with-wrong-pass",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModesReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent,
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrAuth,
				msg:    "Access denied",
			},
		},
		"Error on authentication client denied because of wrong password after retry": {
			clientOptions: append(slices.Clone(singleBrokerClientOptions),
				pam_test.WithGetPreviousBrokerReturn(&firstBrokerInfo.Id, nil),
				pam_test.WithIsAuthenticatedWantChallenge("gdm-good-password"),
				pam_test.WithIsAuthenticatedMaxRetries(1),
			),
			messages: []tea.Msg{
				userSelected{username: "daemon-selected-user-and-broker-with-wrong-pass"},
				testGdmWaitForStage{
					stage: pam_proto.Stage_challenge,
					events: []*gdm.EventData{
						{
							Type: gdm.EventType_isAuthenticatedRequested,
							Data: &gdm.EventData_IsAuthenticatedRequested{
								IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
									AuthenticationData: &authd.IARequest_AuthenticationData{
										Item: &authd.IARequest_AuthenticationData_Challenge{
											Challenge: "gdm-wrong-password",
										},
									},
								},
							},
						},
					},
					commands: []tea.Cmd{
						tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg {
							return nil
						}),
						sendEvent(testGdmAddPollResultEvent{
							event: &gdm.EventData{
								Type: gdm.EventType_isAuthenticatedRequested,
								Data: &gdm.EventData_IsAuthenticatedRequested{
									IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
										AuthenticationData: &authd.IARequest_AuthenticationData{
											Item: &authd.IARequest_AuthenticationData_Challenge{
												Challenge: "another-wrong-password",
											},
										},
									},
								},
							},
						}),
					},
				},
			},
			wantUsername:       "daemon-selected-user-and-broker-with-wrong-pass",
			wantSelectedBroker: firstBrokerInfo.Id,
			wantGdmRequests: []gdm.RequestType{
				gdm.RequestType_uiLayoutCapabilities,
				gdm.RequestType_changeStage, // -> broker Selection
				gdm.RequestType_changeStage, // -> authMode Selection
				gdm.RequestType_changeStage, // -> challenge
			},
			wantGdmEvents: []gdm.EventType{
				gdm.EventType_userSelected,
				gdm.EventType_brokersReceived,
				gdm.EventType_brokerSelected,
				gdm.EventType_authModesReceived,
				gdm.EventType_authModeSelected,
				gdm.EventType_uiLayoutReceived,
				gdm.EventType_authEvent, // retry
				gdm.EventType_authEvent, // denied
			},
			wantStage: pam_proto.Stage_challenge,
			wantExitStatus: pamError{
				status: pam.ErrAuth,
				msg:    "Access denied",
			},
		},
	}
	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.clientOptions == nil {
				tc.clientOptions = singleBrokerClientOptions
			}
			if tc.client == nil {
				tc.client = pam_test.NewDummyClient(gdmTestPrivateKey, tc.clientOptions...)
			}

			messagesToSend := tc.messages
			messagesToWait := append(tc.messages, tc.wantMessages...)

			if tc.wantExitStatus != earlyStopExitStatus {
				messagesToWait = append(messagesToWait, tc.wantExitStatus)
			}

			gdmMutex := sync.Mutex{}
			gdmHandler := &gdmConvHandler{
				t:                    t,
				mu:                   &gdmMutex,
				currentStageCond:     *sync.NewCond(&gdmMutex),
				pendingEventsFlushed: make(chan struct{}),
				allRequestsReceived:  make(chan struct{}),
				allEventsReceived:    make(chan struct{}),
				currentStageChanged:  make(chan struct{}),
				pendingEvents:        tc.gdmEvents,
				wantEvents:           tc.wantGdmEvents,
				wantRequests:         tc.wantGdmRequests,
			}
			uiModel := UIModel{
				PamMTx:     pam_test.NewModuleTransactionDummy(gdmHandler),
				ClientType: Gdm,
				Client:     tc.client,
			}
			appState := testGdmUIModel{
				UIModel:             uiModel,
				gdmHandler:          gdmHandler,
				wantMessages:        slices.Clone(messagesToWait),
				wantMessagesHandled: make(chan struct{}),
			}

			if tc.supportedLayouts != nil {
				gdmHandler.supportedLayouts = tc.supportedLayouts
			} else {
				gdmHandler.supportedLayouts = []*authd.UILayout{pam_test.FormUILayout()}
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
				tea.WithFilter(appState.filterFunc),
				tea.WithoutCatchPanics(),
				// Explicitly set the output to something so that the program
				// won't try to init some terminal fancy things that also appear
				// to be racy...
				// See: https://github.com/charmbracelet/bubbletea/issues/910
				tea.WithOutput(devNull),
			}
			p := tea.NewProgram(&appState, teaOpts...)
			appState.program = p

			// testHadTimeout := false
			controlDone := make(chan struct{})
			go func() {
				wg := sync.WaitGroup{}
				if len(messagesToWait) > 0 {
					for _, m := range messagesToSend {
						t.Logf("Sent message %#v\n", m)
						p.Send(m)
					}
					wg.Add(1)
					go func() {
						t.Log("Waiting for wantMessagesHandled", messagesToWait)
						<-appState.wantMessagesHandled
						t.Log("DONE waiting for wantMessagesHandled")
						wg.Done()
					}()
				}
				if len(tc.gdmEvents) > 0 {
					wg.Add(1)
					go func() {
						t.Log("Waiting for pendingEventsFlushed")
						<-gdmHandler.pendingEventsFlushed
						t.Log("DONE waiting for pendingEventsFlushed")
						wg.Done()
					}()
				}
				if len(tc.wantGdmRequests) > 0 {
					wg.Add(1)
					go func() {
						t.Log("Waiting for allRequestsReceived")
						<-gdmHandler.allRequestsReceived
						wg.Done()
						t.Log("DONE waiting for allRequestsReceived")
					}()
				}
				if len(tc.wantGdmEvents) > 0 {
					wg.Add(1)
					go func() {
						t.Log("Waiting for allEventsReceived")
						<-gdmHandler.allEventsReceived
						wg.Done()
						t.Log("DONE waiting for allEventsReceived")
					}()
				}

				t.Log("Waiting for expected events")
				waitChan := make(chan struct{})
				go func() {
					wg.Wait()
					close(waitChan)
				}()
				select {
				case <-time.After(5 * time.Second):
				case <-waitChan:
				}
				t.Log("Waiting for events done...")

				// Ensure we've nothing to send back...
				select {
				case <-time.After(gdmPollFrequency * 2):
					// All good, it seems there's nothing coming.
				case <-gdmHandler.pendingEventsFlushed:
				}
				t.Log("Waiting for flushing events done...")

				defer close(controlDone)
				t.Log("Time to quit!")
				appState.programShouldQuit.Store(true)
				p.Send(tea.Quit())
			}()
			_, err = p.Run()
			require.NoError(t, err)

			logStatus := func() {
				appState.mu.Lock()
				defer appState.mu.Unlock()
				gdmHandler.mu.Lock()
				defer gdmHandler.mu.Unlock()

				receivedEventTypes := []gdm.EventType{}
				for _, e := range gdmHandler.receivedEvents {
					receivedEventTypes = append(receivedEventTypes, e.Type)
				}

				t.Log("----------------")
				t.Logf("Remaining msgs: %#v\n", appState.wantMessages)
				t.Log("----------------")
				t.Logf("Received events: %#v\n", receivedEventTypes)
				t.Logf("Wanted events: %#v\n", tc.wantGdmEvents)
				t.Log("----------------")
				t.Logf("Handled requests: %#v\n", gdmHandler.handledRequests)
				t.Logf("Wanted requests: %#v\n", tc.wantGdmRequests)
				t.Log("----------------")
			}

			select {
			case <-time.After(5 * time.Second):
				logStatus()
				t.Fatalf("timeout waiting for test expected results")
			case <-controlDone:
			}

			gdmHandler.mu.Lock()
			defer gdmHandler.mu.Unlock()

			appState.mu.Lock()
			defer appState.mu.Unlock()

			if tc.wantExitStatus.Message() == gdmTestIgnoredMessage {
				switch wantRet := tc.wantExitStatus.(type) {
				case PamReturnError:
					exitErr, ok := appState.ExitStatus().(PamReturnError)
					require.True(t, ok, "exit status should be an error")
					require.Equal(t, wantRet.Status(), exitErr.Status())
				case PamSuccess:
					_, ok := appState.ExitStatus().(PamSuccess)
					require.True(t, ok, "exit status should be a success")
				default:
					t.Fatalf("Unexpected exit status: %v", wantRet)
				}
			} else {
				require.Equal(t, tc.wantExitStatus, appState.ExitStatus())
			}

			for _, req := range tc.wantNoGdmRequests {
				require.NotContains(t, gdmHandler.handledRequests, req)
			}

			require.Equal(t, tc.wantStage, gdmHandler.currentStage,
				"GDM Stage does not match with expected one")

			for _, req := range tc.wantGdmRequests {
				// We don't do full equal check since we only care about having received
				// the ones explicitly listed.
				require.Contains(t, gdmHandler.handledRequests, req)
			}

			receivedEventTypes := []gdm.EventType{}
			for _, e := range gdmHandler.receivedEvents {
				receivedEventTypes = append(receivedEventTypes, e.Type)
			}
			require.True(t, isSupersetOf(receivedEventTypes, tc.wantGdmEvents),
				"Required events have not been received: %#v vs %#v", tc.wantGdmEvents, receivedEventTypes)

			require.Empty(t, appState.wantMessages, "Wanted messages have not all been processed")

			if _, ok := tc.wantExitStatus.(PamReturnError); ok && tc.wantExitStatus != earlyStopExitStatus {
				// If the model exited with error and that matches, we don't
				// care much comparing all the expectations, since the final exit status
				// is matching what we expect.
				return
			}

			if tc.wantBrokers == nil {
				availableBrokers, err := appState.Client.AvailableBrokers(context.TODO(), nil)
				require.NoError(t, err)
				tc.wantBrokers = availableBrokers.GetBrokersInfos()
			}

			requireEqualData(t, tc.wantBrokers, gdmHandler.receivedBrokers)
			require.Equal(t, tc.wantSelectedBroker, gdmHandler.selectedBrokerID)

			username, err := appState.PamMTx.GetItem(pam.User)
			require.NoError(t, err)
			require.Equal(t, tc.wantUsername, username)
		})
	}
}

func requireEqualData(t *testing.T, want any, actual any) {
	t.Helper()

	wantJSON, err := json.MarshalIndent(want, "", "  ")
	require.NoError(t, err)
	actualJSON, err := json.MarshalIndent(actual, "", "  ")
	require.NoError(t, err)

	require.Equal(t, wantJSON, actualJSON)
}

func TestMain(m *testing.M) {
	var err error
	gdmTestPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	defer pam_test.MaybeDoLeakCheck()
	if err != nil {
		panic(fmt.Sprintf("could not create an valid rsa key: %v", err))
	}
	os.Exit(m.Run())
}
