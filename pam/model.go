package main

import (
	"context"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/log"
)

var debug string

// sessionInfo contains the global broker session information.
type sessionInfo struct {
	brokerID      string
	sessionID     string
	encryptionKey string
}

// model is the global models orchestrator.
type model struct {
	pamMTx pam.ModuleTransaction
	client authd.PAMClient

	height              int
	width               int
	interactiveTerminal bool

	currentSession *sessionInfo

	userSelectionModel     userSelectionModel
	brokerSelectionModel   brokerSelectionModel
	authModeSelectionModel authModeSelectionModel
	authenticationModel    authenticationModel

	exitStatus pamReturnStatus
}

/* global events */

// UsernameOrBrokerListReceived is received either when the user name is filled (pam or manually) and we got the broker list.
type UsernameOrBrokerListReceived struct{}

// BrokerSelected signifies that the broker has been chosen.
type BrokerSelected struct {
	BrokerID string
}

// SessionStarted signals that we started a session with a given broker.
type SessionStarted struct {
	brokerID      string
	sessionID     string
	encryptionKey string
}

// GetAuthenticationModesRequested signals that a model needs to get the broker authentication modes.
type GetAuthenticationModesRequested struct{}

// AuthModeSelected is triggered when the authentication mode has been chosen.
type AuthModeSelected struct {
	ID string
}

// UILayoutReceived means that we got the ui layout to display by the broker.
type UILayoutReceived struct {
	layout *authd.UILayout
}

// SessionEnded signals that the session is done and closed from the broker.
type SessionEnded struct{}

// Init initializes the main model orchestrator.
func (m *model) Init() tea.Cmd {
	m.exitStatus = pamError{status: pam.ErrSystem, msg: "model did not return anything"}
	m.userSelectionModel = newUserSelectionModel(m.pamMTx)
	var cmds []tea.Cmd
	cmds = append(cmds, m.userSelectionModel.Init())

	m.brokerSelectionModel = newBrokerSelectionModel(m.client)
	cmds = append(cmds, m.brokerSelectionModel.Init())

	m.authModeSelectionModel = newAuthModeSelectionModel()
	cmds = append(cmds, m.authModeSelectionModel.Init())

	m.authenticationModel = newAuthenticationModel(m.client)
	cmds = append(cmds, m.authenticationModel.Init())

	cmds = append(cmds, m.changeStage(Stage_userSelection))
	return tea.Batch(cmds...)
}

// Update handles events and actions to be done from the main model orchestrator.
func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	log.Debugf(context.TODO(), "%+v", msg)

	switch msg := msg.(type) {
	// Key presses
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, sendEvent(pamError{
				status: pam.ErrAbort,
				msg:    "cancel requested",
			})
		case "esc":
			if m.brokerSelectionModel.WillCaptureEscape() || m.authModeSelectionModel.WillCaptureEscape() {
				break
			}
			var cmd tea.Cmd
			switch m.currentStage() {
			case Stage_brokerSelection:
				cmd = m.changeStage(Stage_userSelection)
			case Stage_authModeSelection:
				cmd = m.changeStage(Stage_brokerSelection)
			case Stage_challenge:
				cmd = m.changeStage(Stage_authModeSelection)
			}
			return m, cmd
		}

	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.width = msg.Width
		m.brokerSelectionModel.SetHeight(m.height - 3)
		m.brokerSelectionModel.SetWidth(m.width)

	// Exit cases
	case pamReturnStatus:
		m.exitStatus = msg
		return m, m.quit()

	// Events
	case UsernameOrBrokerListReceived:
		if m.username() == "" {
			return m, nil
		}
		if m.availableBrokers() == nil {
			return m, nil
		}

		// Got user and brokers? Time to auto or manually select.
		return m, tea.Sequence(
			m.changeStage(Stage_brokerSelection),
			AutoSelectForUser(m.client, m.username()))

	case BrokerSelected:
		return m, startBrokerSession(m.client, msg.BrokerID, m.username())

	case SessionStarted:
		m.currentSession = &sessionInfo{
			brokerID:      msg.brokerID,
			sessionID:     msg.sessionID,
			encryptionKey: msg.encryptionKey,
		}
		return m, sendEvent(GetAuthenticationModesRequested{})

	case GetAuthenticationModesRequested:
		if m.currentSession == nil || !m.authModeSelectionModel.IsReady() {
			return m, nil
		}

		return m, tea.Sequence(
			getAuthenticationModes(m.client, m.currentSession.sessionID, m.authModeSelectionModel.SupportedUILayouts()),
			m.changeStage(Stage_authModeSelection),
		)

	case AuthModeSelected:
		// Reselection/reset of current authentication mode requested (button clicked for instance)
		if msg.ID == "" {
			msg.ID = m.authModeSelectionModel.currentAuthModeSelectedID
		}
		if msg.ID == "" {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    "reselection of current auth mode without current ID",
			})
		}
		return m, getLayout(m.client, m.currentSession.sessionID, msg.ID)

	case UILayoutReceived:
		log.Info(context.TODO(), "UILayoutReceived")

		return m, tea.Sequence(
			m.authenticationModel.Compose(m.currentSession.brokerID, m.currentSession.sessionID, msg.layout),
			m.changeStage(Stage_challenge))

	case SessionEnded:
		m.currentSession = nil
		return m, nil
	}

	var cmd tea.Cmd
	var cmds tea.BatchMsg
	m.userSelectionModel, cmd = m.userSelectionModel.Update(msg)
	cmds = append(cmds, cmd)
	m.brokerSelectionModel, cmd = m.brokerSelectionModel.Update(msg)
	cmds = append(cmds, cmd)
	m.authModeSelectionModel, cmd = m.authModeSelectionModel.Update(msg)
	cmds = append(cmds, cmd)
	m.authenticationModel, cmd = m.authenticationModel.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// View renders a text view of the whole UI.
func (m *model) View() string {
	var view strings.Builder

	log.Info(context.TODO(), m.currentStage())
	switch m.currentStage() {
	case Stage_userSelection:
		view.WriteString(m.userSelectionModel.View())
	case Stage_brokerSelection:
		view.WriteString(m.brokerSelectionModel.View())
	case Stage_authModeSelection:
		view.WriteString(m.authModeSelectionModel.View())
	case Stage_challenge:
		view.WriteString(m.authenticationModel.View())
	default:
		view.WriteString("INVALID STAGE")
	}

	if debug != "" {
		view.WriteString(debug)
	}

	return view.String()
}

// currentStage returns our current stage step.
func (m *model) currentStage() Stage {
	if m.userSelectionModel.Focused() {
		return Stage_userSelection
	}
	if m.brokerSelectionModel.Focused() {
		return Stage_brokerSelection
	}
	if m.authModeSelectionModel.Focused() {
		return Stage_authModeSelection
	}
	if m.authenticationModel.Focused() {
		return Stage_challenge
	}
	return Stage_userSelection
}

// changeStage returns a command acting to change the current stage and reset any previous views.
func (m *model) changeStage(s Stage) tea.Cmd {
	if m.currentStage() != s {
		switch m.currentStage() {
		case Stage_userSelection:
			m.userSelectionModel.Blur()
		case Stage_brokerSelection:
			m.brokerSelectionModel.Blur()
		case Stage_authModeSelection:
			m.authModeSelectionModel.Blur()
		case Stage_challenge:
			m.authenticationModel.Blur()
		}
	}

	switch s {
	case Stage_userSelection:
		// The session should be ended when going back to previous state, but we don’t quit the stage immediately
		// and so, we should always ensure we cancel previous session.
		return tea.Sequence(endSession(m.client, m.currentSession), m.userSelectionModel.Focus())

	case Stage_brokerSelection:
		m.authModeSelectionModel.Reset()
		return tea.Sequence(endSession(m.client, m.currentSession), m.brokerSelectionModel.Focus())

	case Stage_authModeSelection:
		m.authenticationModel.Reset()

		return m.authModeSelectionModel.Focus()

	case Stage_challenge:
		return m.authenticationModel.Focus()
	}

	// TODO: error
	return nil
}

// username returns currently selected user name.
func (m model) username() string {
	return m.userSelectionModel.Value()
}

// availableBrokers returns currently available brokers.
func (m model) availableBrokers() []*authd.ABResponse_BrokerInfo {
	return m.brokerSelectionModel.availableBrokers
}
