//go:generate go run github.com/msteinert/pam/cmd/pam-moduler -libname "pam_authd.so" -no-main
//go:generate go generate --skip="pam_module.go"

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam"
	"github.com/sirupsen/logrus"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/consts"
	"github.com/ubuntu/authd/internal/log"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var pamModuleHandler pam.ModuleHandler = &pamModule{}

// pamModule is the structure that implements the pam.ModuleHandler interface
// that is called during pam operations.
type pamModule struct {
}

const (
	// authenticationBrokerIDKey is the Key used to store the data in the
	// PAM module for the second stage authentication to select the default
	// broker for the current user.
	authenticationBrokerIDKey = "authentication-broker-id"
)

/*
	FIXME: provide instructions using pam-auth-update instead!
	Add to /etc/pam.d/common-auth
	auth    [success=3 default=die ignore=ignore]   pam_authd.so
*/

// Authenticate is the method that is invoked during pam_authenticate request.
func (h *pamModule) Authenticate(mt *pam.ModuleTransaction, flags pam.Flags,
	args []string) error {
	return h.authenticate(mt, flags, args)
}

func (h *pamModule) authenticate(mt PamModuleTransaction, flags pam.Flags,
	args []string) error {
	// Initialize localization
	// TODO

	// Attach logger and info handler.
	// TODO

	interactiveTerminal := term.IsTerminal(int(os.Stdin.Fd()))

	client, closeConn, err := newClient(args)
	if err != nil {
		log.Debug(context.TODO(), err)
		return pam.AuthinfoUnavail
	}
	defer closeConn()

	appState := model{
		pamMt:               mt,
		client:              client,
		interactiveTerminal: interactiveTerminal,
	}

	if err := mt.SetData(authenticationBrokerIDKey, nil); err != nil {
		return err
	}

	//tea.WithInput(nil)
	//tea.WithoutRenderer()
	var opts []tea.ProgramOption
	if !interactiveTerminal {
		opts = append(opts, tea.WithInput(nil), tea.WithoutRenderer())
	}
	p := tea.NewProgram(&appState, opts...)
	if _, err := p.Run(); err != nil {
		log.Errorf(context.TODO(), "Cancelled authentication: %v", err)
		return pam.Abort
	}

	var status = newPamStatus(pam.SystemErr, errors.New("unknown exit code"))

	switch exitMsg := appState.exitStatus.(type) {
	case pamSuccess:
		if err := mt.SetData(authenticationBrokerIDKey, exitMsg.brokerID); err != nil {
			return err
		}
		status = exitMsg
	case pamIgnore:
		// localBrokerID is only set on pamIgnore if the user has chosen local broker.
		if err := mt.SetData(authenticationBrokerIDKey, exitMsg.localBrokerID); err != nil {
			return err
		}
		status = exitMsg
	case pamReturnStatus:
		status = exitMsg
	}

	if status.Status() != pam.Success && status.Status() != pam.Ignore {
		if _, err := mt.StartStringConv(pam.ErrorMsg, status.Error()); err != nil {
			log.Errorf(context.TODO(), "Failed reporting error to pam: %v", err)
		}
	} else if status.Error() != "" {
		if _, err := mt.StartStringConv(pam.TextInfo, status.Error()); err != nil {
			log.Errorf(context.TODO(), "Failed sending info to pam: %v", err)
		}
	}

	return status
}

// AcctMgmt sets any used brokerID as default for the user.
func (h *pamModule) AcctMgmt(mt *pam.ModuleTransaction, flags pam.Flags,
	args []string) error {
	return h.acctMgmt(mt, flags, args)
}

func (h *pamModule) acctMgmt(mt PamModuleTransaction, flags pam.Flags,
	args []string) error {
	brokerData, err := mt.GetData(authenticationBrokerIDKey)
	if err != nil && errors.Is(err, pam.NoModuleData) {
		return pam.Ignore
	}

	brokerIDUsedToAuthenticate, ok := brokerData.(string)
	// Only set the brokerID as default if we stored one after authentication.
	if !ok || brokerIDUsedToAuthenticate == "" {
		return pam.Ignore
	}

	// Get current user for broker
	user, err := mt.GetItem(pam.User)
	if err != nil {
		return err
	}

	if user == "" {
		log.Infof(context.TODO(), "can't get user from PAM")
		return pam.Ignore
	}

	client, closeConn, err := newClient(args)
	if err != nil {
		log.Debugf(context.TODO(), "%s", err)
		return pam.Ignore
	}
	defer closeConn()

	req := authd.SDBFURequest{
		BrokerId: brokerIDUsedToAuthenticate,
		Username: user,
	}
	if _, err := client.SetDefaultBrokerForUser(context.TODO(), &req); err != nil {
		log.Infof(context.TODO(), "Can't set default broker  (%q) for %q: %v", brokerIDUsedToAuthenticate, user, err)
		return pam.Ignore
	}

	return nil
}

// newClient returns a new GRPC client ready to emit requests
func newClient(args []string) (client authd.PAMClient, close func(), err error) {
	conn, err := grpc.Dial("unix://"+getSocketPath(args), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("could not connect to authd: %v", err)
	}
	return authd.NewPAMClient(conn), func() { conn.Close() }, nil
}

// getSocketPath returns the socket path to connect to which can be overridden manually.
func getSocketPath(args []string) string {
	socketPath := consts.DefaultSocketPath
	for _, arg := range args {
		opt, optarg, _ := strings.Cut(arg, "=")
		switch opt {
		case "socket":
			socketPath = optarg
		default:
		}
	}
	return socketPath
}

// SetCred is the method that is invoked during pam_setcred request.
func (h *pamModule) SetCred(*pam.ModuleTransaction, pam.Flags, []string) error {
	return pam.Ignore
}

// ChangeAuthTok is the method that is invoked during pam_chauthtok request.
func (h *pamModule) ChangeAuthTok(*pam.ModuleTransaction, pam.Flags, []string) error {
	return pam.Ignore
}

// OpenSession is the method that is invoked during pam_open_session request.
func (h *pamModule) OpenSession(*pam.ModuleTransaction, pam.Flags, []string) error {
	return pam.Ignore
}

// CloseSession is the method that is invoked during pam_close_session request.
func (h *pamModule) CloseSession(*pam.ModuleTransaction, pam.Flags, []string) error {
	return pam.Ignore
}

// Simulating pam on the CLI for manual testing
func main() {
	log.SetLevel(log.DebugLevel)
	f, err := os.OpenFile("/tmp/logdebug", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	logrus.SetOutput(f)

	module := &pamModule{}

	authResult := module.Authenticate(nil, pam.Flags(0), nil)
	fmt.Println("Auth return:", authResult)

	// Simulate setting auth broker as default.
	accMgmtResult := module.AcctMgmt(nil, pam.Flags(0), nil)
	fmt.Println("Acct mgmt return:", accMgmtResult)
}
