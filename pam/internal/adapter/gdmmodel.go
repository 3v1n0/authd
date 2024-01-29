package adapter

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/brokers/responses"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/gdm"
	"github.com/ubuntu/authd/pam/internal/proto"
)

const (
	gdmPollFrequency time.Duration = time.Millisecond * 16
)

// FIXME, MFA:
/*
dic 02 02:26:55 ubuntu-vmware org.gnome.Shell.desktop[35592]: GDM: Got probelem
on gdm-okta : authentication status failure: rpc error: code = Unknown desc = can't
check authentication: IsAuthenticated already running for session
"f35fe0d0-bd0c-4918-a96d-5c36271f81dd"
*/

type gdmModel struct {
	pamMTx pam.ModuleTransaction
}

type gdmPollDone struct{}

func newGdmModel(mTx pam.ModuleTransaction) gdmModel {
	return gdmModel{
		pamMTx: mTx,
	}
}

// Init initializes the main model orchestrator.
func (m *gdmModel) Init() tea.Cmd {
	return tea.Sequence(m.protoHello(),
		requestUICapabilities(m.pamMTx),
		m.pollGdm())
}

func (m *gdmModel) protoHello() tea.Cmd {
	reply, err := gdm.SendData(m.pamMTx, &gdm.Data{Type: gdm.DataType_hello})
	if err != nil {
		return sendEvent(pamError{
			status: pam.ErrCredUnavail,
			msg:    fmt.Sprintf("gdm initialization failed: %v", err),
		})
	}
	if reply.Type != gdm.DataType_hello || reply.Hello == nil ||
		reply.Hello.Version != gdm.ProtoVersion {
		return sendEvent(pamError{
			status: pam.ErrCredUnavail,
			msg: fmt.Sprintf("Gdm protocol initialization failed, type %s, data %#v",
				reply.Type, reply.Hello),
		})
	}
	log.Debugf(context.TODO(), "Gdm Reply is %v", reply)
	return nil
}

func requestUICapabilities(mTx pam.ModuleTransaction) tea.Cmd {
	return func() tea.Msg {
		// res, err := gdm.SendRequest(m.pamMt, &gdm.RequestData_UiLayoutCapabilities{})
		// fixme conversion
		res, err := gdm.SendRequestTyped[*gdm.ResponseData_UiLayoutCapabilities](mTx,
			&gdm.RequestData_UiLayoutCapabilities{})
		if err != nil {
			return pamError{
				status: pam.ErrSystem,
				msg:    fmt.Sprintf("sending GDM Request failed: %v", err),
			}
		}
		// log.Debugf(context.TODO(), "Gdm Request response is %v", responseData)
		if res == nil {
			return supportedUILayoutsReceived{}
		}
		// res, ok := responseData.(*gdm.ResponseData_UiLayoutCapabilities)
		// if !ok {
		// 	log.Debugf(context.TODO(), "Gdm ui capabilities are %v", capabilities)
		// }
		// capabilities := res.UiLayoutCapabilities.SupportedUiLayouts
		// log.Debugf(context.TODO(), "Gdm ui capabilities are %v", capabilities)
		// if err != nil {
		// 	return pamError{
		// 		status: pam.ErrSystem,
		// 		msg:    fmt.Sprintf("parsing GDM response failed: %v", err),
		// 	}
		// }
		return supportedUILayoutsReceived{res.UiLayoutCapabilities.SupportedUiLayouts}
	}
}

// var num = 0

func (m *gdmModel) pollGdm() tea.Cmd {
	// return func() tea.Msg {
	// if num == 2 {
	// 	return pamError{status: pam.ErrSystem,
	// 		msg: fmt.Sprintf("Sending GDM poll STOP")}
	// }
	// num++
	gdmPollResults, err := gdm.SendPoll(m.pamMTx)
	if err != nil {
		return sendEvent(pamError{
			status: pam.ErrSystem,
			msg:    fmt.Sprintf("Sending GDM poll failed: %v", err),
		})
	}
	log.Debugf(context.TODO(), "Gdm Poll response is %v", gdmPollResults)

	commands := []tea.Cmd{sendEvent(gdmPollDone{})}

	for _, result := range gdmPollResults {
		switch res := result.Data.(type) {
		case *gdm.EventData_UserSelected:
			commands = append(commands, sendEvent(userSelected{
				username: res.UserSelected.UserId,
			}))

		case *gdm.EventData_BrokerSelected:
			if res.BrokerSelected == nil {
				return sendEvent(pamError{status: pam.ErrSystem,
					msg: "missing broker selected",
				})
			}
			// Emit BrokerSelected instead?
			commands = append(commands, sendEvent(brokerSelected{
				brokerID: res.BrokerSelected.BrokerId,
			}))

		case *gdm.EventData_AuthModeSelected:
			if res.AuthModeSelected == nil {
				return sendEvent(pamError{
					status: pam.ErrSystem, msg: "missing auth mode id",
				})
			}
			commands = append(commands, selectAuthMode(res.AuthModeSelected.AuthModeId))

		case *gdm.EventData_IsAuthenticatedRequested:
			if res.IsAuthenticatedRequested == nil || res.IsAuthenticatedRequested.AuthenticationData == nil {
				return sendEvent(pamError{
					status: pam.ErrSystem, msg: "missing auth requested",
				})
			}
			commands = append(commands, sendEvent(isAuthenticatedRequested{
				item: res.IsAuthenticatedRequested.GetAuthenticationData().Item,
			}))

		case *gdm.EventData_ReselectAuthMode:
			commands = append(commands, sendEvent(reselectAuthMode{}))

		case *gdm.EventData_StageChanged:
			if res.StageChanged == nil {
				return sendEvent(pamError{
					status: pam.ErrSystem, msg: "missing stage changed",
				})
			}
			log.Infof(context.TODO(), "GDM Stage changed to %s", res.StageChanged.Stage)

			if res.StageChanged.Stage != proto.Stage_challenge {
				// Maybe this can be sent only if we ever hit the challenge phase.
				commands = append(commands, sendEvent(isAuthenticatedCancelled{}))
			}
			commands = append(commands, sendEvent(ChangeStage{res.StageChanged.Stage}))
		}
	}
	return tea.Batch(commands...)
	// }
}

func (m *gdmModel) emitEvent(event gdm.Event) tea.Cmd {
	return func() tea.Msg {
		return m.emitEventSync(event)
	}
}

func (m *gdmModel) emitEventSync(event gdm.Event) tea.Msg {
	err := gdm.EmitEvent(m.pamMTx, event)
	log.Debug(context.TODO(), "EventSend", event, "result", err)
	if err != nil {
		return pamError{
			status: pam.ErrSystem,
			msg:    fmt.Sprintf("Sending GDM event failed: %v", err),
		}
	}
	return nil
}

func (m gdmModel) Update(msg tea.Msg) (gdmModel, tea.Cmd) {
	// log.Infof(context.TODO(), "GDM, parsing %#v", msg)
	switch msg := msg.(type) {
	case gdmPollDone:
		return m, tea.Sequence(
			tea.Tick(gdmPollFrequency, func(time.Time) tea.Msg { return nil }),
			m.pollGdm())

	// case gdmUICapabilitiesReceived:
	// 	return m, sendEvent(supportedUILayoutsReceived{msg.uiLayouts})

	case userSelected:
		return m, m.emitEvent(&gdm.EventData_UserSelected{
			UserSelected: &gdm.Events_UserSelected{UserId: msg.username},
		})

	case brokersListReceived:
		return m, m.emitEvent(&gdm.EventData_BrokersReceived{
			BrokersReceived: &gdm.Events_BrokersReceived{BrokersInfos: msg.brokers},
		})

	case brokerSelected:
		log.Debug(context.TODO(), "GDM - broker selected: ", msg.brokerID)
		return m, m.emitEvent(&gdm.EventData_BrokerSelected{
			BrokerSelected: &gdm.Events_BrokerSelected{BrokerId: msg.brokerID},
		})

	case authModesReceived:
		return m, m.emitEvent(&gdm.EventData_AuthModesReceived{
			AuthModesReceived: &gdm.Events_AuthModesReceived{AuthModes: msg.authModes},
		})

	case authModeSelected:
		return m, m.emitEvent(&gdm.EventData_AuthModeSelected{
			AuthModeSelected: &gdm.Events_AuthModeSelected{AuthModeId: msg.id},
		})

	case UILayoutReceived:
		return m, sendEvent(m.emitEventSync(&gdm.EventData_UiLayoutReceived{
			UiLayoutReceived: &gdm.Events_UiLayoutReceived{UiLayout: msg.layout},
		}))

	// case startAuthentication????

	case isAuthenticatedResultReceived:
		if msg.access == responses.AuthCancelled {
			sendEvent(isAuthenticatedCancelled{})
			return m, nil
		}
		if msg.access == "" {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    "No authentication result"})
		}
		return m, sendEvent(m.emitEventSync(&gdm.EventData_AuthEvent{
			AuthEvent: &gdm.Events_AuthEvent{Response: &authd.IAResponse{
				Access: msg.access,
				Msg:    msg.msg,
			}},
		}))
	}
	return m, nil
}

func (m gdmModel) changeStage(s proto.Stage) tea.Cmd {
	return func() tea.Msg {
		_, err := gdm.SendRequest(m.pamMTx, &gdm.RequestData_ChangeStage{
			ChangeStage: &gdm.Requests_ChangeStage{Stage: s},
		})
		/* FIXME: handle logical errors */
		if err != nil {
			return pamError{
				status: pam.ErrSystem,
				msg:    fmt.Sprintf("Changing GDM stage failed: %v", err),
			}
		}
		log.Debugf(context.TODO(), "Gdm stage change to %v sent", s)
		return nil
	}
}
