// Package adapter is the package for the PAM library
package adapter

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

// UIModel is the global models orchestrator.
type UIModel struct {
	// PamMTx is the [pam.ModuleTransaction] used to communicate with PAM.
	PamMTx pam.ModuleTransaction
	// Client is the [authd.PAMClient] handle used to communicate with authd.
	Client authd.PAMClient
	// InteractiveTerminal whether the underlying PAM system is using an interactive terminal.
	InteractiveTerminal bool

	height int
	width  int

	currentSession *sessionInfo

	userSelectionModel     userSelectionModel
	brokerSelectionModel   brokerSelectionModel
	authModeSelectionModel authModeSelectionModel
	authenticationModel    authenticationModel

	exitStatus PamReturnStatus
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
func (m *UIModel) Init() tea.Cmd {
	m.exitStatus = pamError{status: pam.ErrSystem, msg: "model did not return anything"}
	m.userSelectionModel = newUserSelectionModel(m.PamMTx)
	var cmds []tea.Cmd
	cmds = append(cmds, m.userSelectionModel.Init())

	m.brokerSelectionModel = newBrokerSelectionModel(m.Client)
	cmds = append(cmds, m.brokerSelectionModel.Init())

	m.authModeSelectionModel = newAuthModeSelectionModel()
	cmds = append(cmds, m.authModeSelectionModel.Init())

	m.authenticationModel = newAuthenticationModel(m.Client)
	cmds = append(cmds, m.authenticationModel.Init())

	cmds = append(cmds, m.changeStage(Stage_userSelection))
	return tea.Batch(cmds...)
}

// Update handles events and actions to be done from the main model orchestrator.
func (m *UIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
	case PamReturnStatus:
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
			AutoSelectForUser(m.Client, m.username()))

	case BrokerSelected:
		return m, startBrokerSession(m.Client, msg.BrokerID, m.username())

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
			getAuthenticationModes(m.Client, m.currentSession.sessionID, m.authModeSelectionModel.SupportedUILayouts()),
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
		return m, getLayout(m.Client, m.currentSession.sessionID, msg.ID)

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
func (m *UIModel) View() string {
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
func (m *UIModel) currentStage() Stage {
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
func (m *UIModel) changeStage(s Stage) tea.Cmd {
	switch s {
	case Stage_userSelection:
		m.brokerSelectionModel.Blur()
		m.authModeSelectionModel.Blur()
		m.authenticationModel.Blur()

		// The session should be ended when going back to previous state, but we don’t quit the stage immediately
		// and so, we should always ensure we cancel previous session.
		return tea.Sequence(endSession(m.Client, m.currentSession), m.userSelectionModel.Focus())

	case Stage_brokerSelection:
		m.userSelectionModel.Blur()
		m.authModeSelectionModel.Blur()
		m.authenticationModel.Blur()

		m.authModeSelectionModel.Reset()

		return tea.Sequence(endSession(m.Client, m.currentSession), m.brokerSelectionModel.Focus())

	case Stage_authModeSelection:
		m.userSelectionModel.Blur()
		m.brokerSelectionModel.Blur()
		m.authenticationModel.Blur()

		m.authenticationModel.Reset()

		return m.authModeSelectionModel.Focus()

	case Stage_challenge:
		m.userSelectionModel.Blur()
		m.brokerSelectionModel.Blur()
		m.authModeSelectionModel.Blur()

		return m.authenticationModel.Focus()
	}

	// TODO: error
	return nil
}

// ExitStatus exposes the [PamReturnStatus] externally.
func (m *UIModel) ExitStatus() PamReturnStatus {
	return m.exitStatus
}

// username returns currently selected user name.
func (m UIModel) username() string {
	return m.userSelectionModel.Value()
}

// availableBrokers returns currently available brokers.
func (m UIModel) availableBrokers() []*authd.ABResponse_BrokerInfo {
	return m.brokerSelectionModel.availableBrokers
}
