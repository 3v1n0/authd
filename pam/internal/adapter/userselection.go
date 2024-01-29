package adapter

import (
	"context"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd/internal/log"
)

// userSelectionModel allows selecting from PAM or interactively an user.
type userSelectionModel struct {
	textinput.Model

	pamMTx     pam.ModuleTransaction
	clientType PamClientType
}

// userSelected events to select a new username.
type userSelected struct {
	username string
}

// sendUserSelected sends the event to select a new username.
func sendUserSelected(username string) tea.Cmd {
	log.Debug(context.TODO(), "SEND USER SELECTED", username)
	return sendEvent(userSelected{username})
}

// newUserSelectionModel returns an initialized userSelectionModel.
func newUserSelectionModel(clientType PamClientType, mTx pam.ModuleTransaction) userSelectionModel {
	u := textinput.New()
	if clientType != InteractiveTerminal {
		// Cursor events are racy: https://github.com/charmbracelet/bubbletea/issues/909.
		// FIXME: Avoid initializing the text input Model at all.
		u.Cursor.SetMode(cursor.CursorHide)
	}
	u.Prompt = "Username: " // TODO: i18n
	// i18n should be done against user LANG (if set), not current LANG
	u.Placeholder = "user name"

	//TODO: u.Validate
	return userSelectionModel{
		Model: u,

		pamMTx:     mTx,
		clientType: clientType,
	}
}

// Init initializes userSelectionModel, by getting it from PAM if prefilled.
func (m *userSelectionModel) Init() tea.Cmd {
	pamUser, err := m.pamMTx.GetItem(pam.User)
	if err != nil {
		return sendEvent(pamError{status: pam.ErrSystem, msg: err.Error()})
	}
	if pamUser != "" {
		return sendUserSelected(pamUser)
	}
	return nil

	// username := getPAMUser(m.pamh)
	// if !m.gdm && !m.interactiveTerminal && username == "" {
	// 	return func() tea.Msg {
	// 		username, err := pamConv(m.pamh, m.Prompt, PamPromptEchoOn)
	// 		if err != nil {
	// 			return pamAbort{msg: "Username request failed"}
	// 		}
	// 		return userSelected{username}
	// 	}
	// return sendUserSelected(pamUser)
}

// Update handles events and actions.
func (m userSelectionModel) Update(msg tea.Msg) (userSelectionModel, tea.Cmd) {
	switch msg := msg.(type) {
	case userSelected:
		if msg.username != "" {
			// synchronise our internal validated field and the text one.
			m.SetValue(msg.username)
			if err := m.pamMTx.SetItem(pam.User, msg.username); err != nil {
				return m, sendEvent(pamError{status: pam.ErrAbort, msg: err.Error()})
			}
			return m, sendEvent(UsernameOrBrokerListReceived{})
		}
		return m, nil
	}

	if m.clientType != InteractiveTerminal {
		return m, nil
	}

	// interaction events
	if !m.Focused() {
		return m, nil
	}
	switch msg := msg.(type) {
	// Key presses
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			cmd := sendUserSelected(m.Value())
			return m, cmd
		}
	}

	var cmd tea.Cmd
	m.Model, cmd = m.Model.Update(msg)
	return m, cmd
}
