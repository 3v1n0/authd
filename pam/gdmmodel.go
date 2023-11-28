// Package main is the package for the PAM library.
package main

import (
	"context"
	"errors"
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
	reply, err := (&gdm.Data{Type: gdm.Hello}).SendParsed(m.pamMt)
	if err != nil {
		return sendEvent(pam.NewTransactionError(pam.ErrAuthinfoUnavail,
			fmt.Errorf("gdm initialization failed: %w", err)))
	}
	if reply.Type != gdm.Hello || reply.HelloData == nil ||
		reply.HelloData.Version != gdm.ProtoVersion {
		return sendEvent(pam.NewTransactionError(pam.ErrAuthinfoUnavail,
			fmt.Errorf("Gdm protocol initialization failed, type %s, data %d",
				reply.Type.String(), reply.HelloData)))
	}
	log.Debugf(context.TODO(), "Gdm Reply is %v", reply)
	return nil
}

func (m *gdmModel) requestUICapabilities() tea.Cmd {
	return func() tea.Msg {
		responseData, err := gdm.SendRequest(m.pamMt, gdm.UILayoutCapabilities,
			gdm.Object{})
		if err != nil {
			return pam.NewTransactionError(pam.ErrSystem,
				fmt.Errorf("sending GDM Request failed: %w", err))
		}
		// log.Debugf(context.TODO(), "Gdm Request response is %v", responseData)
		if len(responseData) == 0 {
			return supportedUILayoutsReceived{}
		}
		if len(responseData) != 1 {
			return pam.NewTransactionError(pam.ErrSystem,
				fmt.Errorf("unexpected number of capabilities returned: %d",
					len(responseData)))
		}
		capabilities, err := gdm.ParseRawJSON[[]*authd.UILayout](responseData[0])
		log.Debugf(context.TODO(), "Gdm ui capabilities are %v", capabilities)
		if err != nil {
			return pam.NewTransactionError(pam.ErrSystem,
				fmt.Errorf("parsing GDM response failed: %w", err))
		}
		return supportedUILayoutsReceived{*capabilities}
	}
}

// var num = 0

func (m *gdmModel) pollGdm() tea.Cmd {
	// return func() tea.Msg {
	// if num == 2 {
	// 	return pam.NewTransactionError(pam.ErrSystem,
	// 		fmt.Errorf("Sending GDM poll STOP"))
	// }
	// num++
	gdmPollResults, err := gdm.SendPoll(m.pamMt)
	if err != nil {
		return sendEvent(pam.NewTransactionError(pam.ErrSystem,
			fmt.Errorf("Sending GDM poll failed: %w", err)))
	}
	log.Debugf(context.TODO(), "Gdm Poll response is %v", gdmPollResults)

	commands := []tea.Cmd{sendEvent(gdmPollDone{})}

	for _, result := range gdmPollResults {
		if result.Type == gdm.Event {
			switch result.EventType {
			case gdm.BrokerSelected:
				brokerID, err := gdm.ParseRawObject[string](result.EventData,
					"brokerId")
				if err != nil {
					return sendEvent(pam.NewTransactionError(pam.ErrSystem, err))
				}
				commands = append(commands, sendEvent(brokerSelected{
					brokerID: *brokerID,
				}))

			case gdm.AuthModeSelected:
				id, err := gdm.ParseRawObject[string](result.EventData, "id")
				if err != nil {
					return sendEvent(pam.NewTransactionError(pam.ErrSystem, err))
				}
				commands = append(commands, sendEvent(authModeSelected{id: *id}))

			case gdm.IsAuthenticatedRequested:
				challenge, err := gdm.ParseRawObject[string](result.EventData,
					"challenge")
				if err != nil && !errors.Is(err, gdm.ObjectKeyNotFound{}) {
					return sendEvent(pam.NewTransactionError(pam.ErrSystem,
						fmt.Errorf("Failed to parse event challenge value: %w", err)))
				}
				if challenge != nil {
					commands = append(commands, sendEvent(isAuthenticatedRequested{
						challenge: challenge,
					}))
				}

				wait, err := gdm.ParseRawObject[bool](result.EventData, "wait")
				if err != nil && !errors.Is(err, gdm.ObjectKeyNotFound{}) {
					return sendEvent(pam.NewTransactionError(pam.ErrSystem,
						fmt.Errorf("Failed to parse event wait value: %w", err)))
				}
				if wait != nil {
					commands = append(commands, sendEvent(isAuthenticatedRequested{
						wait: wait,
					}))
				}

			case gdm.ReselectAuthMode:
				commands = append(commands, sendEvent(reselectAuthMode{}))

			case gdm.StageChanged:
				stage, _ := gdm.ParseRawObject[stage](result.EventData, "stage")
				if err != nil {
					return sendEvent(pam.NewTransactionError(pam.ErrSystem,
						fmt.Errorf("Failed to parse event stage value: %w", err)))
				}
				log.Debugf(context.TODO(), "GDM Stage changed to %d", *stage)

				if *stage != stageChallenge {
					commands = append(commands, sendEvent(isAuthenticatedCancelled{}))
				}
			}
		}
	}
	return tea.Batch(commands...)
	// }
}

func (m *gdmModel) emitEvent(eventType gdm.EventType, reqData gdm.Object) tea.Cmd {
	return func() tea.Msg {
		err := gdm.EmitEvent(m.pamMt, eventType, reqData)
		if err != nil {
			return pam.NewTransactionError(pam.ErrSystem,
				fmt.Errorf("Sending GDM event failed: %w", err))
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
		return m, m.emitEvent(gdm.BrokersReceived, gdm.Object{
			"brokers": msg.brokers,
		})
	case brokerSelected:
		return m, m.emitEvent(gdm.BrokerSelected, gdm.Object{
			"brokerId": msg.brokerID,
		})
	case authModesReceived:
		return m, m.emitEvent(gdm.AuthModesReceived, gdm.Object{
			"authModes": msg.authModes,
		})
	case authModeSelected:
		return m, m.emitEvent(gdm.AuthModeSelected, gdm.Object{
			"authMode": msg.id,
		})
	case UILayoutReceived:
		return m, m.emitEvent(gdm.UILayoutReceived, gdm.Object{
			"layout": msg.layout,
		})

	case isAuthenticatedResultReceived:
		if msg.access == responses.AuthCancelled {
			return m, nil
		}
		if msg.res == nil {
			return m, sendEvent(pam.NewTransactionError(pam.ErrSystem,
				errors.New("No authentication result")))
		}
		return m, m.emitEvent(gdm.AuthEvent, gdm.Object{
			"result": msg.res,
		})
	}
	return m, nil
}

func (m *gdmModel) changeStage(s stage) tea.Cmd {
	return func() tea.Msg {
		_, err := gdm.SendRequest(m.pamMt, gdm.ChangeStage, gdm.Object{
			"stage": s,
		})
		/* FIXME: handle logical errors */
		if err != nil {
			return pam.NewTransactionError(pam.ErrSystem,
				fmt.Errorf("Changing GDM stage failed: %w", err))
		}
		log.Debugf(context.TODO(), "Gdm stage change to %v sent", s)
		return nil
	}
}
