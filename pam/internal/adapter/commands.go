package adapter

import (
	"context"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/log"
)

// sendEvent sends an event msg to the main event loop.
func sendEvent(msg tea.Msg) tea.Cmd {
	return func() tea.Msg {
		return msg
	}
}

// startBrokerSession returns the sessionID after marking a broker as current.
func startBrokerSession(client authd.PAMClient, brokerID, username string) tea.Cmd {
	return func() tea.Msg {
		if brokerID == "local" {
			return PamIgnore{LocalBrokerID: brokerID}
		}

		// Start a transaction for this user with the broker.
		// TODO: gdm case?
		lang := "C"
		for _, e := range []string{"LANG", "LC_MESSAGES", "LC_ALL"} {
			l := os.Getenv(e)
			if l != "" {
				lang = l
			}
		}
		lang = strings.TrimSuffix(lang, ".UTF-8")

		sbReq := &authd.SBRequest{
			BrokerId: brokerID,
			Username: username,
			Lang:     lang,
		}

		sbResp, err := client.SelectBroker(context.TODO(), sbReq)
		if err != nil {
			return pamError{status: pam.ErrSystem, msg: fmt.Sprintf("can't select broker: %v", err)}
		}

		sessionID := sbResp.GetSessionId()
		if sessionID == "" {
			return pamError{status: pam.ErrSystem, msg: "no session ID returned by broker"}
		}
		encryptionKey := sbResp.GetEncryptionKey()
		if encryptionKey == "" {
			return pamError{status: pam.ErrSystem, msg: "no encryption key returned by broker"}
		}

		return SessionStarted{
			brokerID:      brokerID,
			sessionID:     sessionID,
			encryptionKey: encryptionKey,
		}
	}
}

// getLayout fetches the layout for a given authModeID.
func getLayout(client authd.PAMClient, session *sessionInfo, authModeID string) tea.Cmd {
	return func() tea.Msg {
		session.mu.Lock()
		defer session.mu.Unlock()
		if session.sessionID == "" {
			return nil
		}
		samReq := &authd.SAMRequest{
			SessionId:            session.sessionID,
			AuthenticationModeId: authModeID,
		}
		uiInfo, err := client.SelectAuthenticationMode(context.TODO(), samReq)
		if err != nil {
			// TODO: probably go back to broker selection here
			return pamError{
				status: pam.ErrSystem,
				msg:    fmt.Sprintf("can't select authentication mode: %v", err),
			}
		}

		if uiInfo.UiLayoutInfo == nil {
			// TODO: probably go back to broker selection here
			return pamError{
				status: pam.ErrSystem,
				msg:    "invalid empty UI Layout information from broker",
			}
		}

		return UILayoutReceived{
			layout: uiInfo.GetUiLayoutInfo(),
		}
	}
}

// quit tears down any active session and quit the main loop.
func (m *UIModel) quit() tea.Cmd {
	if m.currentSession == nil {
		return tea.Quit
	}
	return tea.Sequence(endSession(m.Client, m.currentSession), tea.Quit)
}

// endSession requests the broker to end the session.
func endSession(client authd.PAMClient, currentSession *sessionInfo) tea.Cmd {
	if currentSession == nil {
		return nil
	}
	return func() tea.Msg {
		currentSession.mu.Lock()
		defer currentSession.mu.Unlock()
		if currentSession.sessionID == "" {
			return nil
		}
		_, err := client.EndSession(context.Background(), &authd.ESRequest{
			SessionId: currentSession.sessionID,
		})
		if err != nil {
			log.Infof(context.Background(), "Could not end session %q. Considering already done", currentSession.sessionID)
			return nil
		}
		return SessionEnded{}
	}
}
