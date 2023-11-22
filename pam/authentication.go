// Package main is the package for the PAM library
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/msteinert/pam"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/brokers/responses"
	"github.com/ubuntu/authd/internal/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
)

// sendIsAuthenticated sends the authentication challenges or wait request to the brokers.
// The event will contain the returned value from the broker.
func sendIsAuthenticated(ctx context.Context, client authd.PAMClient, sessionID, content string) tea.Cmd {
	return func() tea.Msg {
		res, err := client.IsAuthenticated(ctx, &authd.IARequest{
			SessionId:          sessionID,
			AuthenticationData: content,
		})
		if err != nil {
			if st := status.Convert(err); st.Code() == codes.Canceled {
				return isAuthenticatedResultReceived{
					access: responses.AuthCancelled,
				}
			}
			return pam.NewTransactionError(pam.ErrSystem,
				fmt.Errorf("authentication status failure: %v", err))
		}

		return isAuthenticatedResultReceived{
			access: res.Access,
			msg:    res.Msg,
		}
	}
}

// isAuthenticatedRequested is the internal events signalling that authentication
// with the given challenge or wait has been requested.
type isAuthenticatedRequested struct {
	content string
}

// isAuthenticatedResultReceived is the internal event with the authentication access result
// and data that was retrieved.
type isAuthenticatedResultReceived struct {
	access string
	msg    string
}

// reselectAuthMode signals to restart auth mode selection with the same id (to resend sms or
// reenable the broker).
type reselectAuthMode struct{}

// authenticationComponent is the interface that all sub layout models needs to match.
type authenticationComponent interface {
	Init() tea.Cmd
	Update(msg tea.Msg) (tea.Model, tea.Cmd)
	View() string
	Focus() tea.Cmd
	Blur()
}

// authenticationModel is the orchestrator model of all the authentication sub model layouts.
type authenticationModel struct {
	focused bool

	client authd.PAMClient

	currentModel          authenticationComponent
	currentSessionID      string
	currentBrokerID       string
	cancelIsAuthenticated func()

	errorMsg string
}

// startAuthentication signals that the authentication model can start
// wait:true authentication and reset fields.
type startAuthentication struct{}

// errMsgToDisplay signals from an authentication form to display an error message.
type errMsgToDisplay struct {
	msg string
}

// newAuthenticationModel initializes a authenticationModel which needs to be Compose then.
func newAuthenticationModel(client authd.PAMClient) authenticationModel {
	return authenticationModel{
		client:                client,
		cancelIsAuthenticated: func() {},
	}
}

// Init initializes authenticationModel.
func (m *authenticationModel) Init() tea.Cmd {
	return nil
}

// Update handles events and actions.
func (m *authenticationModel) Update(msg tea.Msg) (authenticationModel, tea.Cmd) {
	switch msg := msg.(type) {
	case reselectAuthMode:
		m.cancelIsAuthenticated()
		return *m, sendEvent(AuthModeSelected{})

	case isAuthenticatedRequested:
		m.cancelIsAuthenticated()
		ctx, cancel := context.WithCancel(context.Background())
		m.cancelIsAuthenticated = cancel
		return *m, sendIsAuthenticated(ctx, m.client, m.currentSessionID, msg.content)

	case isAuthenticatedResultReceived:
		log.Infof(context.TODO(), "isAuthenticatedResultReceived: %v", msg.access)
		switch msg.access {
		case responses.AuthGranted:
			return *m, sendEvent(newPamSuccess(m.currentBrokerID))

		case responses.AuthRetry:
			errorMsg, err := dataToMsg(msg.msg)
			if err != nil {
				return *m, sendEvent(pam.NewTransactionError(pam.ErrSystem, err))
			}
			m.errorMsg = errorMsg
			return *m, sendEvent(startAuthentication{})

		case responses.AuthDenied:
			errMsg := "Access denied"
			if msg, err := dataToMsg(msg.msg); err != nil {
				return *m, sendEvent(pam.NewTransactionError(pam.ErrSystem, err))
			} else if errMsg != "" {
				errMsg = msg
			}
			return *m, sendEvent(pam.NewTransactionError(pam.ErrAuth, errors.New(errMsg)))

		case responses.AuthNext:
			return *m, sendEvent(GetAuthenticationModesRequested{})

		case responses.AuthCancelled:
			// nothing to do
			return *m, nil
		}

	case errMsgToDisplay:
		m.errorMsg = msg.msg
		return *m, nil
	}

	// interaction events
	if !m.Focused() {
		return *m, nil
	}

	var cmd tea.Cmd
	var model tea.Model
	if m.currentModel != nil {
		model, cmd = m.currentModel.Update(msg)
		m.currentModel = convertTo[authenticationComponent](model)
	}
	return *m, cmd
}

// Focus focuses this model.
func (m *authenticationModel) Focus() tea.Cmd {
	m.focused = true

	if m.currentModel == nil {
		return nil
	}
	return m.currentModel.Focus()
}

// Focused returns if this model is focused.
func (m *authenticationModel) Focused() bool {
	return m.focused
}

// Blur releases the focus from this model.
func (m *authenticationModel) Blur() {
	m.focused = false

	if m.currentModel == nil {
		return
	}
	m.currentModel.Blur()
}

// Compose creates and attaches the sub layout models based on UILayout.
func (m *authenticationModel) Compose(brokerID, sessionID string, layout *authd.UILayout) tea.Cmd {
	m.currentBrokerID = brokerID
	m.currentSessionID = sessionID
	m.cancelIsAuthenticated = func() {}

	m.errorMsg = ""

	switch layout.Type {
	case "form":
		form := newFormModel(layout.GetLabel(), layout.GetEntry(), layout.GetButton(), layout.GetWait() == "true")
		m.currentModel = form

	case "qrcode":
		qrcodeModel, err := newQRCodeModel(layout.GetContent(), layout.GetLabel(), layout.GetButton(), layout.GetWait() == "true")
		if err != nil {
			return sendEvent(pam.NewTransactionError(pam.ErrSystem, err))
		}
		m.currentModel = qrcodeModel

	case "newpassword":
		newPasswordModel := newNewPasswordModel(layout.GetLabel(), layout.GetEntry(), layout.GetButton())
		m.currentModel = newPasswordModel

	default:
		return sendEvent(pam.NewTransactionError(pam.ErrSystem,
			fmt.Errorf("unknown layout type: %q", layout.Type)))
	}

	return sendEvent(startAuthentication{})
}

// View renders a text view of the authentication UI.
func (m authenticationModel) View() string {
	if m.currentModel == nil {
		return ""
	}
	contents := []string{m.currentModel.View()}

	errMsg := m.errorMsg
	if errMsg != "" {
		contents = append(contents, errorStyle.Render(errMsg))
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		contents...,
	)
}

// Resets zeroes any internal state on the authenticationModel.
func (m *authenticationModel) Reset() {
	m.cancelIsAuthenticated()
	m.cancelIsAuthenticated = func() {}
	m.currentModel = nil
	m.currentSessionID = ""
	m.currentBrokerID = ""
}

// dataToMsg returns the data message from a given JSON message.
func dataToMsg(data string) (string, error) {
	if data == "" {
		return "", nil
	}

	v := make(map[string]string)
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		err = fmt.Errorf("invalid json data from provider: %v", err)
		log.Warning(context.TODO(), err)
		return "", err
	}
	if len(v) == 0 {
		return "", nil
	}

	r, ok := v["message"]
	if !ok {
		err := fmt.Errorf("no message entry in json data from provider: %v", v)
		log.Debugf(context.TODO(), "%v", err)
		return "", err
	}
	return r, nil
}
