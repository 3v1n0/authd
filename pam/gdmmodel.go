// Package main is the package for the PAM library.
package main

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/brokers/responses"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/gdm"
)

type gdmModel struct {
	pamMt  pam.ModuleTransaction
	client authd.PAMClient
}

type gdmUICapabilitiesReceived struct {
	uiLayouts []*authd.UILayout
}

type gdmPollDone struct{}

func newGdmModel(p *Parameters) gdmModel {
	return gdmModel{
		pamMt:  p.pamMTx,
		client: p.client,
	}
}

// Init initializes the main model orchestrator.
func (m *gdmModel) Init() tea.Cmd {
	return tea.Sequence(m.protoHello(),
		m.requestUICapabilities(),
		m.pollGdm())
}

func (m *gdmModel) protoHello() tea.Cmd {
	reply, err := (&gdm.Data{Type: gdm.DataType_hello}).SendParsed(m.pamMt)
	if err != nil {
		return sendEvent(pamError{
			status: pam.ErrAuthinfoUnavail,
			msg:    fmt.Sprintf("gdm initialization failed: %v", err),
		})
	}
	if reply.Type != gdm.DataType_hello || reply.Hello == nil ||
		reply.Hello.Version != gdm.ProtoVersion {
		return sendEvent(pamError{
			status: pam.ErrAuthinfoUnavail,
			msg: fmt.Sprintf("Gdm protocol initialization failed, type %s, data %#v",
				reply.Type, reply.Hello),
		})
	}
	log.Debugf(context.TODO(), "Gdm Reply is %v", reply)
	return nil
}

func (m *gdmModel) requestUICapabilities() tea.Cmd {
	return func() tea.Msg {
		// res, err := gdm.SendRequest(m.pamMt, &gdm.RequestData_UiLayoutCapabilities{})
		res, err := gdm.SendRequestTyped[*gdm.ResponseData_UiLayoutCapabilities](m.pamMt,
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
	gdmPollResults, err := gdm.SendPoll(m.pamMt)
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
		case *gdm.EventData_BrokerSelected:
			if res.BrokerSelected != nil {
				return sendEvent(pamError{status: pam.ErrSystem,
					msg: "missing broker selected",
				})
			}
			commands = append(commands, sendEvent(brokerSelected{
				brokerID: res.BrokerSelected.BrokerId,
			}))

		case *gdm.EventData_AuthModeSelected:
			if res.AuthModeSelected == nil {
				return sendEvent(pamError{
					status: pam.ErrSystem, msg: "missing auth mode id",
				})
			}
			commands = append(commands, sendEvent(authModeSelected{
				id: res.AuthModeSelected.AuthModeId,
			}))

		case *gdm.EventData_IsAuthenticatedRequested:
			if res.IsAuthenticatedRequested == nil {
				return sendEvent(pamError{
					status: pam.ErrSystem, msg: "missing auth requested",
				})
			}
			if res.IsAuthenticatedRequested.Challenge != nil {
				commands = append(commands, sendEvent(isAuthenticatedRequested{
					challenge: res.IsAuthenticatedRequested.Challenge,
				}))
			}

			if res.IsAuthenticatedRequested.Wait != nil {
				commands = append(commands, sendEvent(isAuthenticatedRequested{
					wait: res.IsAuthenticatedRequested.Wait,
				}))
			}

		case *gdm.EventData_ReselectAuthMode:
			commands = append(commands, sendEvent(reselectAuthMode{}))

		case *gdm.EventData_StageChanged:
			if res.StageChanged == nil {
				return sendEvent(pamError{
					status: pam.ErrSystem, msg: "missing stage changed",
				})
			}
			log.Debugf(context.TODO(), "GDM Stage changed to %d", res.StageChanged.Stage)

			if stage(res.StageChanged.Stage) != stageChallenge {
				commands = append(commands, sendEvent(isAuthenticatedCancelled{}))
			}
		}
	}
	return tea.Batch(commands...)
	// }
}

func (m *gdmModel) emitEvent(event gdm.Event) tea.Cmd {
	return func() tea.Msg {
		err := gdm.EmitEvent(m.pamMt, event)
		if err != nil {
			return pamError{
				status: pam.ErrSystem,
				msg:    fmt.Sprintf("Sending GDM event failed: %v", err),
			}
		}
		log.Debugf(context.TODO(), "Gdm Event sent")
		return nil
		// return GdmSendEventDone{}
	}
}

func (m gdmModel) Update(msg tea.Msg) (gdmModel, tea.Cmd) {
	log.Debugf(context.TODO(), "GDM, parsing %#v", msg)
	switch msg := msg.(type) {
	case gdmPollDone:
		return m, tea.Sequence(
			tea.Tick(time.Millisecond*16, func(time.Time) tea.Msg { return nil }),
			m.pollGdm())

	case gdmUICapabilitiesReceived:
		return m, sendEvent(supportedUILayoutsReceived{msg.uiLayouts})

	case brokersListReceived:
		return m, m.emitEvent(&gdm.EventData_BrokersReceived{
			BrokersReceived: &gdm.Events_BrokersReceived{BrokersInfos: msg.brokers},
		})

	case brokerSelected:
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
		return m, m.emitEvent(&gdm.EventData_UiLayoutReceived{
			UiLayoutReceived: &gdm.Events_UiLayoutReceived{UiLayout: msg.layout},
		})

	case isAuthenticatedResultReceived:
		if msg.access == responses.AuthCancelled {
			return m, nil
		}
		if msg.res == nil {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    "No authentication result"})
		}
		return m, m.emitEvent(&gdm.EventData_AuthEvent{
			AuthEvent: &gdm.Events_AuthEvent{Response: msg.res},
		})
	}
	return m, nil
}

func (m *gdmModel) changeStage(s stage) tea.Cmd {
	return func() tea.Msg {
		_, err := gdm.SendRequest(m.pamMt, &gdm.RequestData_ChangeStage{
			ChangeStage: &gdm.Requests_ChangeStage{Stage: int32(s)},
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
