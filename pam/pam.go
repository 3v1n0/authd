package main

/*
#cgo LDFLAGS: -lpam -fPIC
#include <security/pam_appl.h>
#include <security/pam_ext.h>

*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/sirupsen/logrus"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/consts"
	"github.com/ubuntu/authd/internal/log"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	// brokerIDUsedToAuthenticate global variable is for the second stage authentication to select the default broker for the current user.
	brokerIDUsedToAuthenticate string
)

type ClientType int

const (
	ClientTypeNone ClientType = iota + 1
	ClientTypeTerminal
	ClientTypeStandard
)

//go:generate sh -c "go build -ldflags='-extldflags -Wl,-soname,pam_authd.so' -buildmode=c-shared -o pam_authd.so"

/*
	Add to /etc/pam.d/common-auth
	auth    [success=3 default=die ignore=ignore]   pam_authd.so
*/

func ForwardAndLogError(pamh pamHandle, format string, args ...interface{}) error {
	message := fmt.Sprintf(format, args...)
	log.Error(context.TODO(), message)
	return sendError(pamh, message)
}

//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	// Initialize localization
	// TODO

	// Attach logger and info handler.
	// TODO

	// TODO: Get this value from argc or pam environment
	log.SetLevel(log.DebugLevel)

	interactiveTerminal := term.IsTerminal(int(os.Stdin.Fd()))

	client, closeConn, err := newClient(argc, argv)
	if err != nil {
		log.Debug(context.TODO(), err)
		return C.PAM_AUTHINFO_UNAVAIL
	}
	defer closeConn()

	appState := model{
		pamh:                pamh,
		client:              client,
		interactiveTerminal: interactiveTerminal,
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
		return C.PAM_ABORT
	}

	logErrMsg := "unknown"
	var errCode C.int = C.PAM_SYSTEM_ERR

	switch exitMsg := appState.exitMsg.(type) {
	case pamSuccess:
		brokerIDUsedToAuthenticate = exitMsg.brokerID
		return C.PAM_SUCCESS
	case pamIgnore:
		// localBrokerID is only set on pamIgnore if the user has chosen local broker.
		brokerIDUsedToAuthenticate = exitMsg.localBrokerID
		if exitMsg.String() != "" {
			log.Debugf(context.TODO(), "Ignoring authd authentication: %s", exitMsg)
		}
		logErrMsg = ""
		errCode = C.PAM_IGNORE
	case pamAbort:
		if exitMsg.String() != "" {
			logErrMsg = fmt.Sprintf("cancelled authentication: %s", exitMsg)
		}
		errCode = C.PAM_ABORT
	case pamAuthError:
		if exitMsg.String() != "" {
			logErrMsg = fmt.Sprintf("authentication: %s", exitMsg)
		}
		errCode = C.PAM_AUTH_ERR
	case pamAuthInfoUnavailable:
		if exitMsg.String() != "" {
			logErrMsg = fmt.Sprintf("missing authentication data: %s", exitMsg)
		}
		errCode = C.PAM_AUTHINFO_UNAVAIL
	case pamSystemError:
		if exitMsg.String() != "" {
			logErrMsg = fmt.Sprintf("system: %s", exitMsg)
		}
		errCode = C.PAM_SYSTEM_ERR
	}

	if logErrMsg != "" {
		ForwardAndLogError(pamh, logErrMsg)
	}

	return errCode
}

// pam_sm_acct_mgmt sets any used brokerID as default for the user.
//
//export pam_sm_acct_mgmt
func pam_sm_acct_mgmt(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	// Only set the brokerID as default if we stored one after authentication.
	if brokerIDUsedToAuthenticate == "" {
		return C.PAM_IGNORE
	}

	// Get current user for broker
	user := getPAMUser(pamh)
	if user == "" {
		log.Infof(context.TODO(), "can't get user from PAM")
		return C.PAM_IGNORE
	}

	client, closeConn, err := newClient(argc, argv)
	if err != nil {
		log.Debugf(context.TODO(), "%s", err)
		return C.PAM_IGNORE
	}
	defer closeConn()

	req := authd.SDBFURequest{
		BrokerId: brokerIDUsedToAuthenticate,
		Username: user,
	}
	if _, err := client.SetDefaultBrokerForUser(context.TODO(), &req); err != nil {
		log.Infof(context.TODO(), "Can't set default broker  (%q) for %q: %v", brokerIDUsedToAuthenticate, user, err)
		return C.PAM_IGNORE
	}

	return C.PAM_SUCCESS
}

// newClient returns a new GRPC client ready to emit requests
func newClient(argc C.int, argv **C.char) (client authd.PAMClient, close func(), err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "unix://"+getSocketPath(argc, argv),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	if err != nil {
		log.Debugf(context.TODO(), "%s", err)
		return nil, nil, fmt.Errorf("could not connect to authd: %v", err)
	}
	return authd.NewPAMClient(conn), func() { conn.Close() }, nil
}

// getSocketPath returns the socket path to connect to which can be overridden manually.
func getSocketPath(argc C.int, argv **C.char) string {
	socketPath := consts.DefaultSocketPath
	for _, arg := range sliceFromArgv(argc, argv) {
		opt, optarg, _ := strings.Cut(arg, "=")
		switch opt {
		case "socket":
			socketPath = optarg
		default:
		}
	}
	return socketPath
}

//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	return C.PAM_IGNORE
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

	authResult := pam_sm_authenticate(nil, 0, 0, nil)
	fmt.Println("Auth return:", authResult)

	// Simulate setting auth broker as default.
	accMgmtResult := pam_sm_acct_mgmt(nil, 0, 0, nil)
	fmt.Println("Acct mgmt return:", accMgmtResult)
}
