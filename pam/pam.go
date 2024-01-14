// Package main is the package for the PAM library.
package main

import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/consts"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/gdm"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

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

func showPamMessage(mTx pam.ModuleTransaction, style pam.Style, msg string) error {
	fmt.Println("Sending message", style, msg)
	switch style {
	case pam.TextInfo, pam.ErrorMsg:
	default:
		return fmt.Errorf("message style not supported: %v", style)
	}
	if _, err := mTx.StartStringConv(style, msg); err != nil {
		log.Errorf(context.TODO(), "Failed sending message to pam: %v", err)
		return err
	}
	return nil
}

func sendReturnMessageToPam(mTx pam.ModuleTransaction, retStatus pamReturnStatus) {
	msg := retStatus.Message()
	if msg == "" {
		return
	}

	style := pam.ErrorMsg
	switch retStatus.(type) {
	case pamIgnore, pamSuccess:
		style = pam.TextInfo
	}

	_ = showPamMessage(mTx, style, msg)
}

func ForwardAndLogError(mt pam.ModuleTransaction, format string, args ...interface{}) {
	if _, err := mt.StartStringConvf(pam.ErrorMsg, format, args); err != nil {
		log.Errorf(context.TODO(), "Failed reporting error to pam: %v", err)
	}
}

func PromptForInt(pamMt pam.ModuleTransaction, title string, choices []string, prompt string) (
	r int, err error) {
	pamPrompt := title

	for {
		pamPrompt += fmt.Sprintln()
		for i, msg := range choices {
			pamPrompt += fmt.Sprintf("%d - %s\n", i+1, msg)
		}

		ret, err := pamMt.StartStringConv(pam.PromptEchoOn, pamPrompt[:len(pamPrompt)-1])
		if err != nil {
			return 0, fmt.Errorf("error while reading stdin: %v", err)
		}
		if ret.Response() == "r" {
			return -1, nil
		}
		if ret.Response() == "" {
			r = 1
		}

		choice, err := strconv.Atoi(ret.Response())
		if err != nil || choice <= 0 || choice > len(choices) {
			log.Errorf(context.TODO(), "Invalid entry. Try again or type 'r'.")
			continue
		}

		return choice - 1, nil
	}
}

// Authenticate is the method that is invoked during pam_authenticate request.
func (h *pamModule) Authenticate(mTx pam.ModuleTransaction, flags pam.Flags, args []string) error {
	// Initialize localization
	// TODO

	// Attach logger and info handler.
	// TODO

	// TODO: Get this value from argc or pam environment
	log.SetLevel(log.DebugLevel)
	fmt.Println("Authentication started!")

	// TODO: Define user options, like disable interactive terminal always

	// FIXME: Ignore root user

	interactiveTerminal := false
	isGdm := false

	fmt.Println("GDM PROTOCOL SUPPORTED",
		gdm.IsPamExtensionSupported(gdm.PamExtensionCustomJSON))

	if gdm.IsPamExtensionSupported(gdm.PamExtensionCustomJSON) {
		isGdm = true

		// reply, err := (&gdm.Data{Type: gdm.Hello}).SendParsed(mt)
		// if err != nil {
		// 	ForwardAndLogError(mt, "Gdm initialization failed: %v", err)
		// 	return pam.AuthinfoUnavail
		// }
		// if reply.Type != gdm.Hello || reply.HelloData == nil ||
		// 	reply.HelloData.Version != gdm.ProtoVersion {
		// 	ForwardAndLogError(mt, "Gdm protocol initialization failed, type %s, data %d",
		// 		reply.Type.String(), reply.HelloData)
		// 	return pam.AuthinfoUnavail
		// }
		// log.Debugf(context.TODO(), "Gdm Reply is %v", reply)
	} else {
		interactiveTerminal = term.IsTerminal(int(os.Stdin.Fd()))
	}

	client, closeConn, err := newClient(args)
	if err != nil {
		log.Debug(context.TODO(), err)
		_ = showPamMessage(mTx, pam.ErrorMsg, err.Error())
		return errors.Join(err, pam.ErrAuthinfoUnavail)
	}
	defer closeConn()

	appState := model{
		Parameters: Parameters{
			pamMTx:              mTx,
			client:              client,
			interactiveTerminal: interactiveTerminal,
			gdm:                 isGdm,
		},
	}

	fmt.Printf("%#v\n", appState.Parameters)

	if err := mTx.SetData(authenticationBrokerIDKey, nil); err != nil {
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
		return pam.ErrAbort
	}

	sendReturnMessageToPam(mTx, appState.exitStatus)

	fmt.Printf("Module done, exit status is %#v\n", appState.exitStatus)

	switch exitStatus := appState.exitStatus.(type) {
	case pamSuccess:
		if err := mTx.SetData(authenticationBrokerIDKey, exitStatus.brokerID); err != nil {
			return err
		}
		if err := mTx.SetItem(pam.User, "marco"); err != nil {
			return err
		}
		return nil

	case pamIgnore:
		// localBrokerID is only set on pamIgnore if the user has chosen local broker.
		if err := mTx.SetData(authenticationBrokerIDKey, exitStatus.localBrokerID); err != nil {
			return err
		}
		return fmt.Errorf("%w: %s", exitStatus.Status(), exitStatus.Message())

	case pamReturnError:
		return fmt.Errorf("%w: %s", exitStatus.Status(), exitStatus.Message())
	}

	return fmt.Errorf("%w: unknown exit code", pam.ErrSystem)
}

// AcctMgmt sets any used brokerID as default for the user.
func (h *pamModule) AcctMgmt(mTx pam.ModuleTransaction, flags pam.Flags, args []string) error {
	brokerData, err := mTx.GetData(authenticationBrokerIDKey)
	if err != nil && errors.Is(err, pam.ErrNoModuleData) {
		return pam.ErrIgnore
	}

	brokerIDUsedToAuthenticate, ok := brokerData.(string)
	if !ok {
		msg := fmt.Sprintf("broker data as an invalid type %#v", brokerData)
		log.Errorf(context.TODO(), msg)
		_ = showPamMessage(mTx, pam.ErrorMsg, msg)
		return pam.ErrIgnore
	}

	// Only set the brokerID as default if we stored one after authentication.
	if brokerIDUsedToAuthenticate == "" {
		return pam.ErrIgnore
	}

	// Get current user for broker
	user, err := mTx.GetItem(pam.User)
	if err != nil {
		return err
	}

	if user == "" {
		log.Infof(context.TODO(), "can't get user from PAM")
		return pam.ErrIgnore
	}

	client, closeConn, err := newClient(args)
	if err != nil {
		log.Debugf(context.TODO(), "%s", err)
		return pam.ErrAuthinfoUnavail
	}
	defer closeConn()

	req := authd.SDBFURequest{
		BrokerId: brokerIDUsedToAuthenticate,
		Username: user,
	}
	if _, err := client.SetDefaultBrokerForUser(context.TODO(), &req); err != nil {
		log.Infof(context.TODO(), "Can't set default broker  (%q) for %q: %v", brokerIDUsedToAuthenticate, user, err)
		return pam.ErrIgnore
	}

	return nil
}

// newClient returns a new GRPC client ready to emit requests.
func newClient(args []string) (client authd.PAMClient, close func(), err error) {
	conn, err := grpc.Dial("unix://"+getSocketPath(args), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("could not connect to authd: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()
	for conn.GetState() != connectivity.Ready {
		if !conn.WaitForStateChange(waitCtx, conn.GetState()) {
			conn.Close()
			return nil, func() {}, fmt.Errorf("could not connect to authd: %w", waitCtx.Err())
		}
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
func (h *pamModule) SetCred(pam.ModuleTransaction, pam.Flags, []string) error {
	return pam.ErrIgnore
}

// ChangeAuthTok is the method that is invoked during pam_chauthtok request.
func (h *pamModule) ChangeAuthTok(pam.ModuleTransaction, pam.Flags, []string) error {
	return pam.ErrIgnore
}

// OpenSession is the method that is invoked during pam_open_session request.
func (h *pamModule) OpenSession(pam.ModuleTransaction, pam.Flags, []string) error {
	return pam.ErrIgnore
}

// CloseSession is the method that is invoked during pam_close_session request.
func (h *pamModule) CloseSession(pam.ModuleTransaction, pam.Flags, []string) error {
	return pam.ErrIgnore
}

// go_pam_cleanup_module is called by the go-loader PAM module during onload.
//
//export go_pam_cleanup_module
func go_pam_cleanup_module() {
	runtime.GC()
}
