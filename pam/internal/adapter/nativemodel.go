package adapter

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam/v2"
	"github.com/skip2/go-qrcode"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/brokers"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/proto"
)

type nativeModel struct {
	pamMTx pam.ModuleTransaction

	availableBrokers []*authd.ABResponse_BrokerInfo
	authModes        []*authd.GAMResponse_AuthenticationMode
	selectedAuthMode string
	uiLayout         *authd.UILayout

	currentStage proto.Stage
}

const nativeCancelKey = "r"

// nativeBrokerSelection is the internal event to notify that a stage change is requested.
type nativeChangeStage ChangeStage

// nativeUserSelection is the internal event that an user needs to be (re)set.
type nativeUserSelection struct{}

// nativeBrokerSelection is the internal event that a broker needs to be (re)selected.
type nativeBrokerSelection struct{}

// nativeAuthSelection is used to require the user input for auth selection.
type nativeAuthSelection struct{}

// nativeChallengeRequested is used to require the user input for challenge.
type nativeChallengeRequested struct{}

// nativeGoBack is a message to require to go back to previous stage.
type nativeGoBack struct{}

var errGoBack = errors.New("request to go back")
var errEmptyResponse = errors.New("empty response received")

// Init initializes the main model orchestrator.
func (m *nativeModel) Init() tea.Cmd {
	m.currentStage = proto.Stage(-1)

	return func() tea.Msg {
		required, optional := "required", "optional"
		supportedEntries := "optional:chars,chars_password,digits,digits_password"
		requiredWithBooleans := "required:true,false"
		optionalWithBooleans := "optional:true,false"

		return supportedUILayoutsReceived{
			layouts: []*authd.UILayout{
				{
					Type:   "form",
					Label:  &required,
					Entry:  &supportedEntries,
					Wait:   &optionalWithBooleans,
					Button: &optional,
				},
				{
					Type:    "qrcode",
					Content: &required,
					Wait:    &requiredWithBooleans,
					Label:   &optional,
					Button:  &optional,
				},
				{
					Type:   "newpassword",
					Label:  &required,
					Entry:  &supportedEntries,
					Button: &optional,
				},
			},
		}
	}
}

func maybeSendPamError(err error) tea.Cmd {
	if err == nil {
		return nil
	}
	var pe pam.Error
	if errors.As(err, &pe) {
		return sendEvent(pamError{status: pe, msg: err.Error()})
	}
	return sendEvent(pamError{status: pam.ErrSystem, msg: err.Error()})
}

func (m nativeModel) changeStage(stage proto.Stage) tea.Cmd {
	return sendEvent(nativeChangeStage{stage})
}

func (m nativeModel) Update(msg tea.Msg) (nativeModel, tea.Cmd) {
	log.Debugf(context.TODO(), "Native model update: %#v", msg)

	switch msg := msg.(type) {
	case nativeChangeStage:
		m.currentStage = msg.Stage

	case nativeGoBack:
		return m, m.goBackCommand()

	case userRequired:
		if m.currentStage == proto.Stage_userSelection {
			// We may receive multiple concurrent requests, but due to the sync nature
			// of this model, we can't just accept them once we've one in progress already
			log.Debug(context.TODO(), "User selection already in progress")
			return m, nil
		}
		return m, sendEvent(nativeUserSelection{})

	case nativeUserSelection:
		if err := m.pamMTx.SetItem(pam.User, ""); err != nil {
			return m, maybeSendPamError(err)
		}

		return m, func() tea.Msg {
			user, err := m.promptForInput(pam.PromptEchoOn, "Username")
			if errors.Is(err, errEmptyResponse) {
				return nativeUserSelection{}
			}
			if err != nil && !errors.Is(err, errGoBack) {
				return maybeSendPamError(err)()
			}
			return userSelected{user}
		}

	case userSelected:
		if err := m.pamMTx.SetItem(pam.User, msg.username); err != nil {
			return m, maybeSendPamError(err)
		}

	case brokersListReceived:
		m.availableBrokers = msg.brokers

	case authModesReceived:
		m.authModes = msg.authModes

	case brokerSelectionRequired:
		if m.currentStage == proto.Stage_brokerSelection {
			// We may receive multiple concurrent requests, but due to the sync nature
			// of this model, we can't just accept them once we've one in progress already
			log.Debug(context.TODO(), "Broker selection already in progress")
			return m, nil
		}
		return m, sendEvent(nativeBrokerSelection{})

	case nativeBrokerSelection:
		if len(m.availableBrokers) < 1 {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    "No brokers available to select",
			})
		}

		if len(m.availableBrokers) == 1 {
			return m, sendEvent(brokerSelected{brokerID: m.availableBrokers[0].Id})
		}

		var choices []choicePair
		for _, b := range m.availableBrokers {
			choices = append(choices, choicePair{id: b.Id, label: b.Name})
		}

		return m, func() tea.Msg {
			id, err := m.promptForChoice("Broker selection", choices, "Select broker")
			if errors.Is(err, errGoBack) {
				return nativeGoBack{}
			}
			if err != nil {
				return pamError{
					status: pam.ErrSystem,
					msg:    fmt.Sprintf("broker selection error: %v", err),
				}
			}
			return brokerSelected{brokerID: id}
		}

	case nativeAuthSelection:
		if len(m.authModes) < 1 {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    "Can't authenticate without authentication modes",
			})
		}

		if len(m.authModes) == 1 {
			return m, sendEvent(authModeSelected{id: m.authModes[0].Id})
		}

		var choices []choicePair
		for _, am := range m.authModes {
			choices = append(choices, choicePair{id: am.Id, label: am.Label})
		}

		id, err := m.promptForChoice("Authentication mode selection", choices,
			"Select authentication mode")
		if errors.Is(err, errGoBack) {
			m.authModes = nil
			return m, sendEvent(nativeGoBack{})
		}
		if errors.Is(err, errEmptyResponse) {
			return m, sendEvent(nativeChallengeRequested{})
		}
		if err != nil {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    fmt.Sprintf("broker selection error: %v", err),
			})
		}

		return m, sendEvent(authModeSelected{id: id})

	case authModeSelected:
		m.selectedAuthMode = msg.id

	case UILayoutReceived:
		m.uiLayout = msg.layout

	case startAuthentication:
		return m, sendEvent(nativeChallengeRequested{})

	case nativeChallengeRequested:
		return m, m.startChallenge()

	case isAuthenticatedResultReceived:
		access := msg.access
		authMsg, err := dataToMsg(msg.msg)
		if err != nil {
			return m, sendEvent(pamError{status: pam.ErrSystem, msg: err.Error()})
		}

		switch access {
		case brokers.AuthGranted:
			return m, maybeSendPamError(m.sendInfo(authMsg))
		case brokers.AuthNext:
			m.uiLayout = nil
			return m, maybeSendPamError(m.sendInfo(authMsg))
		case brokers.AuthDenied, brokers.AuthRetry:
			return m, maybeSendPamError(m.sendError(authMsg))
		case brokers.AuthCancelled:
			return m, sendEvent(isAuthenticatedCancelled{})
		default:
			return m, maybeSendPamError(m.sendError("Access %q is not valid", access))
		}

	case isAuthenticatedCancelled:
		m.uiLayout = nil
		return m, sendEvent(nativeGoBack{})
	}

	return m, nil
}

func checkForPromptReplyValidity(reply string) error {
	switch reply {
	case nativeCancelKey:
		return errGoBack
	case "", "\n":
		return errEmptyResponse
	default:
		return nil
	}
}

func (m nativeModel) promptForInput(style pam.Style, prompt string) (string, error) {
	resp, err := m.pamMTx.StartStringConvf(style, "%s: ", prompt)
	if err != nil {
		return "", err
	}
	return resp.Response(), checkForPromptReplyValidity(resp.Response())
}

func (m nativeModel) promptForNumericInput(style pam.Style, prompt string) (int, error) {
	for {
		out, err := m.promptForInput(style, prompt)
		if err != nil {
			return -1, err
		}
		intOut, err := strconv.Atoi(out)
		if err == nil {
			return intOut, nil
		}

		err = m.sendError("Provided input can't be parsed as integer value")
		if err != nil {
			return -1, err
		}
	}
}

func (m nativeModel) promptForNumericInputAsString(style pam.Style, prompt string) (string, error) {
	input, err := m.promptForNumericInput(style, prompt)
	return fmt.Sprint(input), err
}

func (m nativeModel) sendError(errorMsg string, args ...any) error {
	if errorMsg == "" {
		return nil
	}
	_, err := m.pamMTx.StartStringConvf(pam.ErrorMsg, errorMsg, args...)
	return err
}

func (m nativeModel) sendInfo(infoMsg string, args ...any) error {
	if infoMsg == "" {
		return nil
	}
	_, err := m.pamMTx.StartStringConvf(pam.TextInfo, infoMsg, args...)
	return err
}

type choicePair struct {
	id    string
	label string
}

func (m nativeModel) promptForChoice(title string, choices []choicePair, prompt string) (string, error) {
	for {
		msg := fmt.Sprintf("== %s (use '%s' to go back) ==\n", title, nativeCancelKey)
		for i, choice := range choices {
			msg += fmt.Sprintf("%d - %s\n", i+1, choice.label)
		}

		msg += prompt
		idx, err := m.promptForNumericInput(pam.PromptEchoOn, msg)
		if err != nil {
			return "", err
		}
		// TODO: Maybe add support for default selection...

		if idx < 1 || idx > len(choices) {
			if err := m.sendError("Invalid entry. Try again or input '%s'.", nativeCancelKey); err != nil {
				return "", err
			}
			continue
		}

		return choices[idx-1].id, nil
	}
}

func (m nativeModel) startChallenge() tea.Cmd {
	if m.uiLayout == nil {
		return sendEvent(pamError{
			status: pam.ErrSystem,
			msg:    "Can't authenticate without ui layout selected",
		})
	}

	hasWait := m.uiLayout.GetWait() == "true"

	switch m.uiLayout.Type {
	case "form":
		return m.handleFormChallenge(hasWait)

	case "qrcode":
		if !hasWait {
			return sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    "Can't handle qrcode without waiting",
			})
		}
		return m.handleQrCode()

	case "newpassword":
		return m.handleNewPassword()

	default:
		return sendEvent(pamError{
			status: pam.ErrSystem,
			msg:    fmt.Sprintf("Unknown layout type: %q", m.uiLayout.Type),
		})
	}
}

func (m nativeModel) handleFormChallenge(hasWait bool) tea.Cmd {
	if buttonLabel := m.uiLayout.GetButton(); buttonLabel != "" {
		authMode := "selected authentication mode"
		authModeIdx := slices.IndexFunc(m.authModes, func(mode *authd.GAMResponse_AuthenticationMode) bool {
			return mode.Id == m.selectedAuthMode
		})
		if authModeIdx > -1 {
			authMode = m.authModes[authModeIdx].Label
		}
		choices := []choicePair{
			{id: "continue", label: fmt.Sprintf("Proceed with %s", authMode)},
		}
		if buttonLabel := m.uiLayout.GetButton(); buttonLabel != "" {
			choices = append(choices, choicePair{id: "button", label: buttonLabel})
		}

		id, err := m.promptForChoice(authMode, choices, "Select action")
		if errors.Is(err, errGoBack) {
			return sendEvent(nativeGoBack{})
		}
		if errors.Is(err, errEmptyResponse) {
			return sendEvent(nativeChallengeRequested{})
		}
		if err != nil {
			return maybeSendPamError(err)
		}
		if id == "button" {
			return sendEvent(reselectAuthMode{})
		}
	}

	var prompt string
	if m.uiLayout.Label != nil {
		prompt, _ = strings.CutSuffix(*m.uiLayout.Label, ":")
	}

	if prompt == "" {
		switch m.uiLayout.GetEntry() {
		case "digits":
			fallthrough
		case "digits_password":
			prompt = "PIN"
		case "chars":
			prompt = "Value"
		case "chars_password":
			prompt = "Password"
		}
	}

	instructions := "Leave the input field empty or insert '%[1]s' to cancel the request and go back"
	if hasWait {
		// Duplicating some contents here, as it will be better for translators once we've them
		instructions = "Leave the input field empty to wait for other authentication method" +
			"or insert '%[1]s' to go back"
		if m.uiLayout.GetEntry() == "" {
			instructions = "Leave the input field empty to wait for the authentication method" +
				"or insert '%[1]s' to go back"
		}
	}

	if err := m.sendInfo(instructions, nativeCancelKey); err != nil {
		return maybeSendPamError(err)
	}

	challenge, err := m.promptForChallenge(prompt)
	if errors.Is(err, errGoBack) {
		return sendEvent(nativeGoBack{})
	}
	if errors.Is(err, errEmptyResponse) {
		if hasWait {
			return sendAuthWaitCommand()
		}
		err = nil
	}
	if err != nil {
		return maybeSendPamError(err)
	}

	return sendEvent(isAuthenticatedRequested{
		item: &authd.IARequest_AuthenticationData_Challenge{Challenge: challenge},
	})
}

func (m nativeModel) promptForChallenge(prompt string) (string, error) {
	switch m.uiLayout.GetEntry() {
	case "chars", "":
		return m.promptForInput(pam.PromptEchoOn, prompt)
	case "chars_password":
		return m.promptForInput(pam.PromptEchoOff, prompt)
	case "digits":
		return m.promptForNumericInputAsString(pam.PromptEchoOn, prompt)
	case "digits_password":
		return m.promptForNumericInputAsString(pam.PromptEchoOff, prompt)
	default:
		return "", fmt.Errorf("Unhandled entry %q", m.uiLayout.GetEntry())
	}
}

func (m nativeModel) handleQrCode() tea.Cmd {
	qrCode, err := qrcode.New(m.uiLayout.GetContent(), qrcode.Medium)
	if err != nil {
		return sendEvent(pamError{
			status: pam.ErrSystem,
			msg:    fmt.Sprintf("Can't generate qrcode: %v", err),
		})
	}

	if err := m.sendInfo(m.uiLayout.GetLabel()); err != nil {
		return maybeSendPamError(err)
	}

	if err := m.sendInfo(qrCode.ToSmallString(false)); err != nil {
		return maybeSendPamError(err)
	}

	choices := []choicePair{
		{id: "wait", label: "Wait for the QR code scan result"},
	}
	if buttonLabel := m.uiLayout.GetButton(); buttonLabel != "" {
		choices = append(choices, choicePair{id: "button", label: buttonLabel})
	}

	id, err := m.promptForChoice("Qr Code authentication", choices, "Select action")
	if errors.Is(err, errGoBack) {
		return sendEvent(nativeGoBack{})
	}
	if errors.Is(err, errEmptyResponse) {
		return sendAuthWaitCommand()
	}
	if err != nil {
		return maybeSendPamError(err)
	}

	switch id {
	case "button":
		return sendEvent(reselectAuthMode{})
	case "wait":
		return sendAuthWaitCommand()
	default:
		return nil
	}
}

func (m nativeModel) handleNewPassword() tea.Cmd {
	if buttonLabel := m.uiLayout.GetButton(); buttonLabel != "" {
		choices := []choicePair{
			{id: "continue", label: "Proceed with password update"},
		}
		if buttonLabel := m.uiLayout.GetButton(); buttonLabel != "" {
			choices = append(choices, choicePair{id: "button", label: buttonLabel})
		}

		id, err := m.promptForChoice("Password Update", choices, "Select action")
		if errors.Is(err, errGoBack) {
			return sendEvent(nativeGoBack{})
		}
		if errors.Is(err, errEmptyResponse) {
			return sendEvent(nativeChallengeRequested{})
		}
		if err != nil {
			return maybeSendPamError(err)
		}
		if id == "button" {
			return sendEvent(isAuthenticatedRequested{
				item: &authd.IARequest_AuthenticationData_Skip{Skip: "true"},
			})
		}
	}

	showChallenge := func() (string, tea.Cmd) {
		if err := m.sendInfo("Leave the input field empty or insert '%[1]s' to cancel the request and go back",
			nativeCancelKey); err != nil {
			return "", maybeSendPamError(err)
		}
		challenge, err := m.promptForChallenge(m.uiLayout.GetLabel())
		if errors.Is(err, errGoBack) {
			return "", sendEvent(nativeGoBack{})
		}
		if err != nil && !errors.Is(err, errEmptyResponse) {
			return "", maybeSendPamError(err)
		}
		return challenge, nil
	}

	challenge1, cmd := showChallenge()
	if cmd != nil {
		return cmd
	}

	challenge2, cmd := showChallenge()
	if cmd != nil {
		return cmd
	}

	if challenge1 != challenge2 {
		err := m.sendError("Password entries don't match")
		if err != nil {
			return maybeSendPamError(err)
		}
		return m.handleNewPassword()
	}

	return sendEvent(isAuthenticatedRequested{
		item: &authd.IARequest_AuthenticationData_Challenge{Challenge: challenge2},
	})
}

func (m nativeModel) goBackCommand() tea.Cmd {
	return func() tea.Cmd {
		if m.uiLayout != nil {
			return sendEvent(isAuthenticatedCancelled{})
		}

		if m.currentStage > proto.Stage_authModeSelection && len(m.authModes) > 1 {
			return tea.Sequence(
				sendEvent(ChangeStage{proto.Stage_authModeSelection}),
				sendEvent(nativeAuthSelection{}),
			)
		}
		if m.currentStage > proto.Stage_brokerSelection && len(m.availableBrokers) > 1 {
			return tea.Sequence(
				sendEvent(ChangeStage{proto.Stage_brokerSelection}),
				sendEvent(nativeBrokerSelection{}),
			)
		}
		return tea.Sequence(
			sendEvent(ChangeStage{proto.Stage_userSelection}),
			sendEvent(nativeUserSelection{}),
		)
	}()
}

func sendAuthWaitCommand() tea.Cmd {
	return sendEvent(isAuthenticatedRequested{
		item: &authd.IARequest_AuthenticationData_Wait{Wait: "true"},
	})
}
