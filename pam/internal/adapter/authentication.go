package adapter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/brokers"
	"github.com/ubuntu/authd/internal/log"
	pam_proto "github.com/ubuntu/authd/pam/internal/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
)

// sendIsAuthenticated sends the authentication challenges or wait request to the brokers.
// The event will contain the returned value from the broker.
func sendIsAuthenticated(ctx context.Context, client authd.PAMClient, sessionID string,
	authData *authd.IARequest_AuthenticationData) tea.Cmd {
	return func() tea.Msg {
		res, err := client.IsAuthenticated(ctx, &authd.IARequest{
			SessionId:          sessionID,
			AuthenticationData: authData,
		})
		if err != nil {
			if st := status.Convert(err); st.Code() == codes.Canceled {
				return isAuthenticatedResultReceived{
					access: brokers.AuthCancelled,
				}
			}
			return pamError{
				status: pam.ErrSystem,
				msg:    fmt.Sprintf("authentication status failure: %v", err),
			}
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
	item authd.IARequestAuthenticationDataItem
}

// isAuthenticatedResultReceived is the internal event with the authentication access result
// and data that was retrieved.
type isAuthenticatedResultReceived struct {
	access string
	msg    string
}

// isAuthenticatedCancelled is the event to cancel the auth request.
type isAuthenticatedCancelled struct {
	msg string
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

	client     authd.PAMClient
	clientType PamClientType

	currentModel     authenticationComponent
	currentSessionID string
	currentBrokerID  string
	currentChallenge string

	authChan       chan struct{}
	cancelAuthFunc func()

	encryptionKey *rsa.PublicKey

	errorMsg string
}

// startAuthentication signals that the authentication model can start
// wait:true authentication and reset fields.
type startAuthentication struct{}

// errMsgToDisplay signals from an authentication form to display an error message.
type errMsgToDisplay struct {
	msg string
}

// newPasswordCheck is sent to request a new password quality check.
type newPasswordCheck struct {
	challenge string
}

// newPasswordCheckResult returns the password quality check result.
type newPasswordCheckResult struct {
	challenge string
	msg       string
}

// newAuthenticationModel initializes a authenticationModel which needs to be Compose then.
func newAuthenticationModel(client authd.PAMClient, clientType PamClientType) authenticationModel {
	return authenticationModel{
		client:     client,
		clientType: clientType,
	}
}

// Init initializes authenticationModel.
func (m *authenticationModel) Init() tea.Cmd {
	return nil
}

func (m *authenticationModel) cancelIsAuthenticated() tea.Cmd {
	cancelAuthFunc := m.cancelAuthFunc
	if cancelAuthFunc == nil {
		return nil
	}

	return func() tea.Msg {
		cancelAuthFunc()
		return nil
	}
}

// Update handles events and actions.
func (m *authenticationModel) Update(msg tea.Msg) (authModel authenticationModel, command tea.Cmd) {
	switch msg := msg.(type) {
	case reselectAuthMode:
		return *m, tea.Sequence(m.cancelIsAuthenticated(), sendEvent(AuthModeSelected{}))

	case newPasswordCheck:
		res := newPasswordCheckResult{challenge: msg.challenge}
		if err := checkChallengeQuality(m.currentChallenge, msg.challenge); err != nil {
			res.msg = err.Error()
		}
		return *m, sendEvent(res)

	case isAuthenticatedRequested:
		log.Debugf(context.TODO(), "%#v", msg)

		if m.cancelAuthFunc != nil {
			// There's still an authentication in progress, send the request only
			// after we've cancelled it.
			return *m, tea.Sequence(m.cancelIsAuthenticated(), sendEvent(msg))
		}

		// Store the current challenge, if present, for password verifications.
		challenge, ok := msg.item.(*authd.IARequest_AuthenticationData_Challenge)
		if !ok {
			challenge = &authd.IARequest_AuthenticationData_Challenge{Challenge: ""}
		}
		m.currentChallenge = challenge.Challenge

		// no challenge value, pass it as is
		if err := msg.encryptChallengeIfPresent(m.encryptionKey); err != nil {
			return *m, sendEvent(pamError{status: pam.ErrSystem, msg: fmt.Sprintf("could not encrypt challenge payload: %v", err)})
		}

		ctx, cancel := context.WithCancel(context.Background())
		authChan := make(chan struct{})
		m.authChan = authChan
		m.cancelAuthFunc = func() {
			cancel()
			<-authChan
		}
		return *m, sendIsAuthenticated(ctx, m.client, m.currentSessionID, &authd.IARequest_AuthenticationData{Item: msg.item})

	case isAuthenticatedCancelled:
		log.Debugf(context.TODO(), "%#v", msg)
		return *m, m.cancelIsAuthenticated()

	case isAuthenticatedResultReceived:
		log.Debugf(context.TODO(), "%#v", msg)

		// Resets challenge if the authentication wasn't successful.
		defer func() {
			// the returned authModel is a copy of function-level's `m` at this point!
			m := &authModel
			if msg.access != brokers.AuthGranted && msg.access != brokers.AuthNext {
				m.currentChallenge = ""
			}
			if m.cancelAuthFunc != nil {
				m.cancelAuthFunc = nil
				close(m.authChan)
			}
		}()

		switch msg.access {
		case brokers.AuthGranted:
			infoMsg, err := dataToMsg(msg.msg)
			if err != nil {
				return *m, sendEvent(pamError{status: pam.ErrSystem, msg: err.Error()})
			}
			return *m, sendEvent(PamSuccess{BrokerID: m.currentBrokerID, msg: infoMsg})

		case brokers.AuthRetry:
			errorMsg, err := dataToMsg(msg.msg)
			if err != nil {
				return *m, sendEvent(pamError{status: pam.ErrSystem, msg: err.Error()})
			}
			m.errorMsg = errorMsg
			return *m, sendEvent(startAuthentication{})

		case brokers.AuthDenied:
			errMsg, err := dataToMsg(msg.msg)
			if err != nil {
				return *m, sendEvent(pamError{status: pam.ErrSystem, msg: err.Error()})
			}
			if errMsg == "" {
				errMsg = "Access denied"
			}
			return *m, sendEvent(pamError{status: pam.ErrAuth, msg: errMsg})

		case brokers.AuthNext:
			return *m, sendEvent(GetAuthenticationModesRequested{})

		case brokers.AuthCancelled:
			// nothing to do
			return *m, nil
		}

	case errMsgToDisplay:
		m.errorMsg = msg.msg
		return *m, nil
	}

	if m.clientType != InteractiveTerminal {
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

// Compose initialize the authentication model to be used.
// It creates and attaches the sub layout models based on UILayout.
func (m *authenticationModel) Compose(brokerID, sessionID string, encryptionKey *rsa.PublicKey, layout *authd.UILayout) tea.Cmd {
	m.currentBrokerID = brokerID
	m.currentSessionID = sessionID
	m.encryptionKey = encryptionKey
	m.cancelAuthFunc = nil

	m.errorMsg = ""

	if m.clientType != InteractiveTerminal {
		return tea.Sequence(sendEvent(ChangeStage{pam_proto.Stage_challenge}),
			sendEvent(startAuthentication{}))
	}

	switch layout.Type {
	case "form":
		form := newFormModel(layout.GetLabel(), layout.GetEntry(), layout.GetButton(), layout.GetWait() == "true")
		m.currentModel = form

	case "qrcode":
		qrcodeModel, err := newQRCodeModel(layout.GetContent(), layout.GetCode(),
			layout.GetLabel(), layout.GetButton(), layout.GetWait() == "true")
		if err != nil {
			return sendEvent(pamError{status: pam.ErrSystem, msg: err.Error()})
		}
		m.currentModel = qrcodeModel

	case "newpassword":
		newPasswordModel := newNewPasswordModel(layout.GetLabel(), layout.GetEntry(), layout.GetButton())
		m.currentModel = newPasswordModel

	default:
		return sendEvent(pamError{
			status: pam.ErrSystem,
			msg:    fmt.Sprintf("unknown layout type: %q", layout.Type),
		})
	}

	return tea.Sequence(sendEvent(ChangeStage{pam_proto.Stage_challenge}),
		sendEvent(startAuthentication{}))
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
func (m *authenticationModel) Reset() tea.Cmd {
	m.currentModel = nil
	m.currentSessionID = ""
	m.currentBrokerID = ""
	return m.cancelIsAuthenticated()
}

// dataToMsg returns the data message from a given JSON message.
func dataToMsg(data string) (string, error) {
	if data == "" {
		return "", nil
	}

	v := make(map[string]string)
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		return "", fmt.Errorf("invalid json data from provider: %v", err)
	}
	if len(v) == 0 {
		return "", nil
	}

	r, ok := v["message"]
	if !ok {
		return "", fmt.Errorf("no message entry in json data from provider: %v", v)
	}
	return r, nil
}

func (authData *isAuthenticatedRequested) encryptChallengeIfPresent(publicKey *rsa.PublicKey) error {
	// no challenge value, pass it as is
	challenge, ok := authData.item.(*authd.IARequest_AuthenticationData_Challenge)
	if !ok {
		return nil
	}

	ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, []byte(challenge.Challenge), nil)
	if err != nil {
		return err
	}

	// encrypt it to base64 and replace the challenge with it
	base64Encoded := base64.StdEncoding.EncodeToString(ciphertext)
	authData.item = &authd.IARequest_AuthenticationData_Challenge{Challenge: base64Encoded}
	return nil
}
