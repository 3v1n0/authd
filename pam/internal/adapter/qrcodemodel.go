package adapter

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/skip2/go-qrcode"
	"github.com/ubuntu/authd"
)

// qrcodeModel is the form layout type to allow authenticating and return a challenge.
type qrcodeModel struct {
	label       string
	buttonModel *buttonModel

	content string
	code    string
	qrCode  *qrcode.QRCode

	wait bool
}

var centeredStyle = lipgloss.NewStyle().Align(lipgloss.Center, lipgloss.Top)

// newQRCodeModel initializes and return a new qrcodeModel.
func newQRCodeModel(content, code, label, buttonLabel string, wait bool) (qrcodeModel, error) {
	var button *buttonModel
	if buttonLabel != "" {
		button = &buttonModel{label: buttonLabel}
	}

	var qrCode *qrcode.QRCode
	if content != "" {
		var err error
		qrCode, err = qrcode.New(content, qrcode.Medium)
		if err != nil {
			return qrcodeModel{}, fmt.Errorf("can't generate QR code: %v", err)
		}
	}

	return qrcodeModel{
		label:       label,
		buttonModel: button,
		content:     content,
		code:        code,
		qrCode:      qrCode,
		wait:        wait,
	}, nil
}

// Init initializes qrcodeModel.
func (m qrcodeModel) Init() tea.Cmd {
	return nil
}

// Update handles events and actions.
func (m qrcodeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg.(type) {
	case startAuthentication:
		if !m.wait {
			return m, nil
		}
		return m, sendEvent(isAuthenticatedRequested{
			item: &authd.IARequest_AuthenticationData_Wait{Wait: "true"},
		})
	}

	switch msg := msg.(type) {
	// Key presses
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if m.buttonModel == nil {
				return m, nil
			}
			return m, sendEvent(reselectAuthMode{})
		}
	}

	model, cmd := m.buttonModel.Update(msg)
	m.buttonModel = convertTo[*buttonModel](model)

	return m, cmd
}

// View renders a text view of the form.
func (m qrcodeModel) View() string {
	fields := []string{}
	if m.label != "" {
		fields = append(fields, m.label, "")
	}

	qrcodeWidth := 0
	if m.qrCode != nil {
		qr := strings.TrimRight(m.qrCode.ToSmallString(false), "\n")
		fields = append(fields, qr)
		qrcodeWidth = lipgloss.Width(qr)
	}

	style := centeredStyle.Width(qrcodeWidth)
	fields = append(fields, style.Render(m.code))

	if m.buttonModel != nil {
		fields = append(fields, style.Render(m.buttonModel.View()))
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		fields...,
	)
}

// Focus focuses this model.
func (m qrcodeModel) Focus() tea.Cmd {
	if m.buttonModel == nil {
		return nil
	}
	return m.buttonModel.Focus()
}

// Blur releases the focus from this model.
func (m qrcodeModel) Blur() {
	if m.buttonModel == nil {
		return
	}
	m.buttonModel.Blur()
}
