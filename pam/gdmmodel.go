package main

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/gdm"
)

type gdmModel struct {
	pamh   pamHandle
	client authd.PAMClient
}

type GdmUiCapabilitiesReceived struct {
	results any
}

type GdmPollDone struct {
	results []gdm.Data
}

func newGdmModel(p *Parameters) gdmModel {
	return gdmModel{
		pamh:   p.pamh,
		client: p.client,
	}
}

// Init initializes the main model orchestrator.
func (m *gdmModel) Init() tea.Cmd {
	return tea.Sequence(func() tea.Msg {
		gdmData, err := SendGdmRequest(m.pamh, gdm.UiLayoutCapabilities, gdm.Object{})
		if err != nil {
			return pamAbort{msg: fmt.Sprintf("Sending GDM Request failed: %v", err)}
		}
		log.Debugf(context.TODO(), "Gdm Request response is %v", gdmData)
		return GdmUiCapabilitiesReceived{}
	}, m.pollGdm())
}

func (m *gdmModel) pollGdm() tea.Cmd {
	return func() tea.Msg {
		gdmPollResults, err := SendGdmPoll(m.pamh)
		if err != nil {
			return pamAbort{msg: fmt.Sprintf("Sending GDM poll failed: %v", err)}
		}
		log.Debugf(context.TODO(), "Gdm Poll response is %v", gdmPollResults)
		return GdmPollDone{results: gdmPollResults}
	}
}

func (m gdmModel) Update(msg tea.Msg) (gdmModel, tea.Cmd) {
	switch msg.(type) {
	case GdmPollDone:
		// return m, m.pollGdm()
	}
	return m, nil
}
