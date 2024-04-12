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
}

const nativeCancelKey = "r"

// nativeAuthSelectionRequested is used to require the user input for auth selection.
type nativeAuthSelectionRequested struct{}

// nativeChallengeRequested is used to require the user input for challenge.
type nativeChallengeRequested struct{}

var errGoBack = errors.New("request to go back")

// Init initializes the main model orchestrator.
func (m *nativeModel) Init() tea.Cmd {
	return func() tea.Msg {
		required, optional := "required", "optional"
		supportedEntries := "optional:chars,chars_password,digits"
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

func sendPamError(err error) tea.Cmd {
	if err == nil {
		return nil
	}
	var pe pam.Error
	if errors.As(err, &pe) {
		return sendEvent(pamError{status: pe, msg: err.Error()})
	}
	return sendEvent(pamError{status: pam.ErrSystem, msg: err.Error()})
}

func (m nativeModel) Update(msg tea.Msg) (nativeModel, tea.Cmd) {
	switch msg := msg.(type) {
	case userRequired:
		err := m.pamMTx.SetItem(pam.User, "")
		if err != nil {
			return m, sendPamError(err)
		}
		user, err := m.promptForInput("Username")
		if err != nil {
			return m, sendPamError(err)
		}
		return m, sendUserSelected(user)

	case userSelected:
		err := m.pamMTx.SetItem(pam.User, msg.username)
		if err != nil {
			return m, sendPamError(err)
		}

	case brokersListReceived:
		m.availableBrokers = msg.brokers
		for _, b := range m.availableBrokers {
			log.Debugf(context.TODO(), "We have Broker", *b)
		}

	case authModesReceived:
		m.authModes = msg.authModes

	case brokerSelectionRequired:
		if len(m.availableBrokers) < 1 {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    "No brokers available to select",
			})
		}

		if len(m.availableBrokers) == 1 {
			log.Debugf(context.TODO(), "Selecting broker...", m.availableBrokers[0].Id)
			return m, selectBroker(m.availableBrokers[0].Id)
		}

		var choices choicesList
		for _, b := range m.availableBrokers {
			choices = append(choices, choicePair{id: b.Id, label: b.Name})
		}

		id, err := m.promptForChoice("Broker selection", choices, "Select broker")
		if errors.Is(err, errGoBack) {
			return m, tea.Sequence(sendEvent(ChangeStage{proto.Stage_userSelection}),
				sendEvent(userRequired{}))
		}
		if err != nil {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    fmt.Sprintf("broker selection error: %v", err),
			})
		}

		log.Debug(context.TODO(), "Selecting broker...", id)
		return m, selectBroker(id)

	case nativeAuthSelectionRequested:
		if len(m.authModes) < 1 {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    "Can't authenticate without authentication modes",
			})
		}

		if len(m.authModes) == 1 {
			return m, sendEvent(authModeSelected{id: m.authModes[0].Id})
		}

		var choices choicesList
		for _, am := range m.authModes {
			choices = append(choices, choicePair{id: am.Id, label: am.Label})
		}

		id, err := m.promptForChoice("Authentication mode selection", choices,
			"Select authentication mode")
		if errors.Is(err, errGoBack) {
			m.authModes = nil
			if len(m.availableBrokers) < 2 {
				return m, tea.Sequence(sendEvent(ChangeStage{proto.Stage_userSelection}),
					sendEvent(userRequired{}))
			}
			return m, tea.Sequence(sendEvent(ChangeStage{proto.Stage_brokerSelection}),
				sendEvent(brokerSelectionRequired{}))
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
		if m.uiLayout == nil {
			return m, sendEvent(pamError{
				status: pam.ErrSystem,
				msg:    "Can't authenticate without an UI layout selected",
			})
		}
		commands := []tea.Cmd{sendEvent(nativeChallengeRequested{})}
		if wait := m.uiLayout.GetWait(); wait == "true" {
			commands = append(commands, sendEvent(isAuthenticatedRequested{
				item: &authd.IARequest_AuthenticationData_Wait{Wait: wait},
			}))
		}
		return m, tea.Batch(commands...)

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
			return m, sendPamError(m.sendInfo(authMsg))
		case brokers.AuthNext:
			m.uiLayout = nil
			return m, sendPamError(m.sendInfo(authMsg))
		case brokers.AuthDenied, brokers.AuthRetry:
			return m, sendPamError(m.sendError(authMsg))
		case brokers.AuthCancelled:
			return m, sendEvent(isAuthenticatedCancelled{})
		default:
			return m, sendPamError(m.sendError("Access %q is not valid", access))
		}

	case isAuthenticatedCancelled:
		m.uiLayout = nil
		// FIXME: Should we go back to previous stage too?
	}

	return m, nil
}

func (m nativeModel) promptForInput(prompt string) (string, error) {
	resp, err := m.pamMTx.StartStringConvf(pam.PromptEchoOn, "%s: ", prompt)
	if err != nil {
		return "", err
	}
	return resp.Response(), nil
}

func (m nativeModel) promptForNumericInput(prompt string) (int, error) {
	for {
		out, err := m.promptForInput(prompt)
		if err != nil {
			return -1, err
		}
		if out == "" || out == nativeCancelKey {
			return -1, errGoBack
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

func (m nativeModel) promptForNumericInputAsString(prompt string) (string, error) {
	input, err := m.promptForNumericInput(prompt)
	if errors.Is(err, errGoBack) {
		return nativeCancelKey, nil
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprint(input), nil
}

func (m nativeModel) promptForSecret(prompt string) (string, error) {
	resp, err := m.pamMTx.StartStringConvf(pam.PromptEchoOff, "%s: ", prompt)
	if err != nil {
		return "", err
	}
	return resp.Response(), nil
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

type choicesList = []choicePair

func (m nativeModel) promptForChoice(title string, choices choicesList, prompt string) (string, error) {
	for {
		msg := fmt.Sprintf("== %s (use '%s' to go back) ==\n", title, nativeCancelKey)
		for i, choice := range choices {
			msg += fmt.Sprintf("%d - %s\n", i+1, choice.label)
		}

		msg += prompt
		idx, err := m.promptForNumericInput(msg)
		if err != nil {
			return "", err
		}
		// TODO: Maybe add support for default selection...

		if idx < 1 || idx > len(choices) {
			err := m.sendError("Invalid entry. Try again or input '%s'.", nativeCancelKey)
			if err != nil {
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
		choices := choicesList{
			{id: "continue", label: fmt.Sprintf("Proceed with %s", authMode)},
		}
		if buttonLabel := m.uiLayout.GetButton(); buttonLabel != "" {
			choices = append(choices, choicePair{id: "button", label: buttonLabel})
		}

		id, err := m.promptForChoice(authMode, choices, "Select action")
		if errors.Is(err, errGoBack) {
			return m.handleChallengeAnswer(nativeCancelKey, true, nil)
		}
		if err != nil {
			return sendPamError(err)
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

	err := m.sendInfo(instructions, nativeCancelKey)
	if err != nil {
		return sendPamError(err)
	}

	challenge, err := m.promptForChallenge(prompt)
	if err != nil {
		return sendPamError(err)
	}

	return m.handleChallengeAnswer(challenge, hasWait, sendEvent(isAuthenticatedRequested{
		item: &authd.IARequest_AuthenticationData_Challenge{Challenge: challenge},
	}))
}

func (m nativeModel) promptForChallenge(prompt string) (string, error) {
	switch m.uiLayout.GetEntry() {
	case "chars", "":
		return m.promptForInput(prompt)
	case "chars_password":
		return m.promptForSecret(prompt)
	case "digits":
		return m.promptForNumericInputAsString(prompt)
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

	err = m.sendInfo(m.uiLayout.GetLabel())
	if err != nil {
		return sendPamError(err)
	}

	err = m.sendInfo(qrCode.ToSmallString(false))
	if err != nil {
		return sendPamError(err)
	}

	choices := choicesList{
		{id: "wait", label: "Wait for the QR code scan result"},
	}
	if buttonLabel := m.uiLayout.GetButton(); buttonLabel != "" {
		choices = append(choices, choicePair{id: "button", label: buttonLabel})
	}

	choices = append(choices, choicePair{id: "cancel", label: "Cancel"})
	id, err := m.promptForChoice("Qr Code authentication", choices, "Select action")
	if errors.Is(err, errGoBack) {
		return m.handleChallengeAnswer(nativeCancelKey, true, nil)
	}
	if err != nil {
		return sendPamError(err)
	}

	switch id {
	case "button":
		return sendEvent(reselectAuthMode{})
	case "cancel":
		return m.handleChallengeAnswer(nativeCancelKey, true, nil)
	default:
		return nil
	}
}

func (m nativeModel) handleNewPassword() tea.Cmd {
	if buttonLabel := m.uiLayout.GetButton(); buttonLabel != "" {
		choices := choicesList{
			{id: "continue", label: "Proceed with password update"},
		}
		if buttonLabel := m.uiLayout.GetButton(); buttonLabel != "" {
			choices = append(choices, choicePair{id: "button", label: buttonLabel})
		}

		id, err := m.promptForChoice("Password Update", choices, "Select action")
		if errors.Is(err, errGoBack) {
			return m.handleChallengeAnswer(nativeCancelKey, true, nil)
		}
		if err != nil {
			return sendPamError(err)
		}
		if id == "button" {
			return sendEvent(isAuthenticatedRequested{
				item: &authd.IARequest_AuthenticationData_Skip{Skip: "true"},
			})
		}
	}

	showChallenge := func() (string, tea.Cmd) {
		err := m.sendInfo("Leave the input field empty or insert '%[1]s' to cancel the request and go back",
			nativeCancelKey)
		if err != nil {
			return "", sendPamError(err)
		}
		challenge, err := m.promptForChallenge(m.uiLayout.GetLabel())
		if err != nil {
			return "", sendPamError(err)
		}
		cmd := m.handleChallengeAnswer(challenge, false, nil)
		if cmd != nil {
			return "", cmd
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
			return sendPamError(err)
		}
		return m.handleNewPassword()
	}

	return sendEvent(isAuthenticatedRequested{
		item: &authd.IARequest_AuthenticationData_Challenge{Challenge: challenge2},
	})
}

func (m nativeModel) handleChallengeAnswer(challenge string, hasWait bool, defaultCommand tea.Cmd) tea.Cmd {
	goBack := func() tea.Cmd {
		commands := []tea.Cmd{sendEvent(isAuthenticatedCancelled{})}
		if len(m.authModes) > 1 {
			commands = append(commands, sendEvent(ChangeStage{proto.Stage_authModeSelection}),
				sendEvent(nativeAuthSelectionRequested{}))
			return tea.Sequence(commands...)
		}
		commands = append(commands, sendEvent(ChangeStage{proto.Stage_brokerSelection}),
			sendEvent(brokerSelectionRequired{}))
		return tea.Sequence(commands...)
	}

	switch challenge {
	case nativeCancelKey:
		return goBack()
	case "", "\n":
		if hasWait {
			return nil
		}
		return goBack()
	default:
		return defaultCommand
	}
}
