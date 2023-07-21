package main

/*
#cgo LDFLAGS: -lpam -fPIC
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>

char *string_from_argv(int i, char **argv);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/consts"
	"github.com/ubuntu/authd/internal/log"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	errGoBack error = errors.New("needs go back")

	// This variable needs to be global to pass it back in pam_sm_acct_mgmt.
	// It would be better if we could set/get item in PAM with that string.
	globalSessionID string
)

const (
	maxChallengeRetries = 3
)

type ClientType int

const (
	ClientTypeNone ClientType = iota + 1
	ClientTypeTerminal
	ClientTypeStandard
)

type PAMClient interface {
	getClientType() ClientType
	getPamHandler() pamHandle
	getClient() authd.PAMClient
	getSessionID() string
	getSupportedLayouts() []*authd.UILayout
	getAuthenticationModes() []*authd.SBResponse_AuthenticationMode
	getPreferredAuthenticationMode() *authd.SBResponse_AuthenticationMode

	startBrokerSession(brokerID, username string) error
	promptForInt(title string, choices []string, prompt string) (r int, err error)
	selectBrokerInteractive(brokersInfo []*authd.ABResponse_BrokerInfo) (brokerID,
		brokerName string, err error)
	selectAuthenticationModeInteractive() (
		name string, err error)

	formChallenge(*authd.UILayout) (*authd.IAResponse, error)
	qrcodeChallenge(*authd.UILayout) (*authd.IAResponse, error)
}

type PAMClientBase struct {
	clientType ClientType
	pamh       pamHandle
	client     authd.PAMClient

	// These are part of the broker session
	sessionID     string
	encryptionKey string
	authModes     []*authd.SBResponse_AuthenticationMode
}

type PAMClientTerminal struct {
	PAMClientBase
}

func NewPAMClientBase(clientType ClientType, pamh pamHandle,
	client authd.PAMClient) *PAMClientBase {
	return &PAMClientBase{clientType, pamh, client,
		"", "", []*authd.SBResponse_AuthenticationMode{}}
}

func NewPAMClientTerminal(pamh pamHandle, client authd.PAMClient) *PAMClientTerminal {
	return &PAMClientTerminal{*NewPAMClientBase(ClientTypeTerminal, pamh, client)}
}

func (base *PAMClientBase) getClientType() ClientType {
	return base.clientType
}

func (base *PAMClientBase) getPamHandler() pamHandle {
	return base.pamh
}

func (base *PAMClientBase) getClient() authd.PAMClient {
	return base.client
}

func (base *PAMClientBase) getSessionID() string {
	return base.sessionID
}

func (base *PAMClientBase) getAuthenticationModes() []*authd.SBResponse_AuthenticationMode {
	return base.authModes
}

func (base *PAMClientBase) getPreferredAuthenticationMode() *authd.SBResponse_AuthenticationMode {
	return base.authModes[0]
}

//go:generate sh -c "go build -ldflags='-extldflags -Wl,-soname,pam_authd.so' -buildmode=c-shared -o pam_authd.so"

/*
	Add to /etc/pam.d/common-auth
	auth    [success=3 default=die ignore=ignore]   pam_authd.so
*/

func sendAndLogError(pamh pamHandle, message string) error {
	log.Errorf(context.TODO(), message)
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

	module, err := getModuleName(pamh)
	if err != nil {
		sendAndLogError(pamh, fmt.Sprintf("Can't get the module name %v", err))
		return C.PAM_AUTH_ERR
	}
	log.Debugf(context.TODO(), "Module name is %s", module)

	err = sendInfo(pamh, "Hello PAM, this a native conversation!")
	if err != nil {
		log.Error(context.TODO(), err)
		return C.PAM_AUTH_ERR
	}

	client, close, err := newClient(argc, argv)
	if err != nil {
		log.Debugf(context.TODO(), "%s", err)
		return C.PAM_AUTHINFO_UNAVAIL
	}
	defer close()

	// Check if we are in an interactive terminal to see if we can do something
	var pamClient PAMClient
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pamClient = NewPAMClientTerminal(pamh, client)
	} else {
		pamClient = NewPAMClientBase(ClientTypeStandard, pamh, client)
	}

	sendInfo(pamh, fmt.Sprintf("Logging in with mode %v", pamClient.getClientType()))

	// Get current user for broker.
	user, err := getUser(pamh, "login: ")
	if err != nil {
		sendAndLogError(pamh, fmt.Sprintf("Can't get user: %v", err))
		return C.PAM_AUTH_ERR
	}

	brokersInfo, err := client.AvailableBrokers(context.TODO(), &authd.ABRequest{
		UserName: &user,
	})
	if err != nil {
		log.Debugf(context.TODO(), "Could not get current available brokers: %v", err)
		return C.PAM_AUTHINFO_UNAVAIL
	}

	type Stage int
	const (
		StageBrokerSelection Stage = iota
		StageAuthenticationMode
		StageChallenge
	)

	stage := StageBrokerSelection

	var brokerName string
	brokerID := brokersInfo.GetPreviousBroker()
	// ensure previous broker for this user still exists
	if brokerID != "" {
		var stillAlive bool
		for _, b := range brokersInfo.GetBrokersInfos() {
			if b.Id != brokerID {
				continue
			}
			stillAlive = true
			brokerName = b.Name
		}
		if !stillAlive {
			brokerID = ""
		}
	}

	var currentAuthModeName string
	var uiLayout *authd.UILayout

	var challengeRetry int
	for {

		switch stage {
		case StageBrokerSelection:
			// Broker selection and escape
			if brokerID == "" {
				brokerID, brokerName, err = pamClient.selectBrokerInteractive(
					brokersInfo.GetBrokersInfos())
				if err != nil {
					// Do not show error message if we only wanted to reset everything from the start, including user name.
					if !errors.Is(err, errGoBack) {
						sendAndLogError(pamh, fmt.Sprintf("could not get selected broker: %v", err))
					}
					return C.PAM_SYSTEM_ERR
				}
				sendInfo(pamh, fmt.Sprintf("Broker with id %v selected", brokerID))
			}
			if brokerID == "local" {
				return C.PAM_IGNORE
			}
			err = pamClient.startBrokerSession(brokerID, user)
			if err != nil {
				sendAndLogError(pamh, fmt.Sprintf("can't select broker %q: %v", brokerName, err))
				return C.PAM_SYSTEM_ERR
			}

			// Autoselect first one.
			globalSessionID = pamClient.getSessionID()
			currentAuthModeName = pamClient.getPreferredAuthenticationMode().Name
			stage = StageAuthenticationMode

		case StageAuthenticationMode:
			if currentAuthModeName == "" {
				currentAuthModeName, err = pamClient.selectAuthenticationModeInteractive()
				// Return one level up, to broker selection.
				if errors.Is(err, errGoBack) {
					brokerID = ""
					stage = StageBrokerSelection
					continue
				}
				if err != nil {
					sendAndLogError(pamh, fmt.Sprintf("can't select interactively authentication mode: %v", err))
					return C.PAM_SYSTEM_ERR
				}
			}

			// Ask broker for UI specific information.
			samReq := &authd.SAMRequest{
				SessionId:              pamClient.getSessionID(),
				AuthenticationModeName: currentAuthModeName,
			}
			uiInfo, err := client.SelectAuthenticationMode(context.TODO(), samReq)
			if err != nil {
				sendAndLogError(pamh, fmt.Sprintf("can't select authentication mode: %v", err))
				return C.PAM_SYSTEM_ERR
			}

			if uiInfo.UiLayoutInfo == nil {
				sendAndLogError(pamh, fmt.Sprintf("invalid empty UI Layout information from broker"))
				return C.PAM_SYSTEM_ERR
			}

			uiLayout = uiInfo.UiLayoutInfo
			stage = StageChallenge
			challengeRetry = 0

		case StageChallenge:
			var iaResp *authd.IAResponse
			var err error
			// TODO: handle context cancellation to return to previous authentication method selection.

			switch uiLayout.Type {
			case "form":
				iaResp, err = pamClient.formChallenge(uiLayout)
				break

			case "qrcode":
				iaResp, err = pamClient.qrcodeChallenge(uiLayout)
			}

			// Go back to authentication selection.
			if errors.Is(err, errGoBack) {
				currentAuthModeName = ""
				stage = StageAuthenticationMode
				continue
			}

			// Validate answer contains something
			if err == nil && iaResp == nil {
				err = errors.New("empty reponse")
			}
			if err != nil {
				sendAndLogError(pamh, fmt.Sprintf("can't check for authorization: %v", err))
				return C.PAM_SYSTEM_ERR
			}

			// Check if authorized
			switch strings.ToLower(iaResp.Access) {
			case "denied":
				sendError(pamh, "Access Denied")
				challengeRetry++
				if challengeRetry < maxChallengeRetries {
					sendInfo(pamh, "Access Denied")
					continue
				}
				return C.PAM_AUTH_ERR
			case "allowed":
				sendInfo(pamh, fmt.Sprintf("Welcome:\n%s\n", iaResp.UserInfo))
				return C.PAM_SUCCESS
			default:
				// Invalid response
				sendAndLogError(pamh, fmt.Sprintf("Invalid Response: %v", iaResp.Access))
				return C.PAM_SYSTEM_ERR
			}
		}
	}
}

// selectBroker allows interactive broker selection.
// Only one choice will be returned immediately.
func (pamClient *PAMClientBase) selectBrokerInteractive(
	brokersInfo []*authd.ABResponse_BrokerInfo) (brokerID, brokerName string, err error) {
	if len(brokersInfo) < 1 {
		return "", "", errors.New("no broker found")
	}

	// Default choice for one possibility.
	if len(brokersInfo) == 1 {
		return brokersInfo[0].GetId(), brokersInfo[0].GetName(), nil
	}

	var choices []string
	var ids []string
	for _, b := range brokersInfo {
		brokerLabel := b.GetName()
		if b.GetBrandIcon() != "" {
			brokerLabel = fmt.Sprintf("%s, %s", brokerLabel, b.GetBrandIcon())
		}
		choices = append(choices, brokerLabel)
		ids = append(ids, b.GetId())
	}

	i, err := pamClient.promptForInt("= Broker selection =", choices, "Select broker: ")
	if err != nil {
		return "", "", fmt.Errorf("broker selection error: %w", err)
	}

	return ids[i], brokersInfo[i].GetName(), nil
}

func (pamClient *PAMClientBase) getSupportedLayouts() []*authd.UILayout {
	required, optional := "required", "optional"
	supportedEntries := "optional:chars,chars_password"
	waitRequired := "required:true,false"
	waitOptional := "optional:true,false"

	return []*authd.UILayout{
		{
			Type:  "form",
			Label: &required,
			Entry: &supportedEntries,
			Wait:  &waitOptional,
		},
		{
			Type:    "qrcode",
			Content: &required,
			Wait:    &waitRequired,
			Label:   &optional,
		},
	}
}

// startBrokerSession returns the sessionID and available authentication modes after marking a broker as current.
func (pamClient *PAMClientBase) startBrokerSession(brokerID, username string) error {
	// Start a transaction for this user with the broker.
	lang := "C"
	for _, e := range []string{"LANG", "LC_MESSAGES", "LC_ALL"} {
		l := os.Getenv(e)
		if l != "" {
			lang = l
		}
	}
	lang = strings.TrimSuffix(lang, ".UTF-8")
	sbReq := &authd.SBRequest{
		BrokerId:           brokerID,
		Username:           username,
		Lang:               lang,
		SupportedUiLayouts: pamClient.getSupportedLayouts(),
	}

	pamClient.sessionID = ""
	pamClient.encryptionKey = ""
	pamClient.authModes = nil

	sbResp, err := pamClient.client.SelectBroker(context.TODO(), sbReq)
	if err != nil {
		return fmt.Errorf("can't get authentication mode: %v", err)
	}

	sessionId := sbResp.GetSessionId()
	if sessionId == "" {
		return errors.New("no session ID returned by broker")
	}
	encryptionKey := sbResp.GetEncryptionKey()
	if encryptionKey == "" {
		return errors.New("no encryption key returned by broker")
	}
	availableAuthModes := sbResp.GetAuthenticationModes()
	if len(availableAuthModes) == 0 {
		return errors.New("no supported authentication mode available for this broker")
	}

	pamClient.sessionID = sessionId
	pamClient.encryptionKey = encryptionKey
	pamClient.authModes = availableAuthModes

	return nil
}

// selectAuthenticationModeInteractive allows interactive authentication mode selection.
// Only one choice will be returned immediately.
func (pamClient *PAMClientBase) selectAuthenticationModeInteractive() (name string, err error) {
	if len(pamClient.authModes) < 1 {
		return "", errors.New("no authentication mode supported")
	}

	// Default choice for one possibility.
	if len(pamClient.authModes) == 1 {
		return pamClient.authModes[0].GetName(), nil
	}

	var choices []string
	var ids []string
	for _, m := range pamClient.authModes {
		choices = append(choices, m.GetLabel())
		ids = append(ids, m.GetName())
	}

	i, err := pamClient.promptForInt("= Authentication mode =",
		choices, "Select authentication mode ('r' to cancel)")
	if err != nil {
		return "", fmt.Errorf("authentication mode selection error: %w", err)
	}

	return ids[i], nil
}

func (pamClient *PAMClientBase) promptForInt(title string, choices []string, prompt string) (
	r int, err error) {
	pamPrompt := title

	for {
		pamPrompt += fmt.Sprintln()
		for i, msg := range choices {
			pamPrompt += fmt.Sprintf("%d - %s\n", i+1, msg)
		}

		var r, err = requestInput(pamClient.pamh, pamPrompt[:len(pamPrompt)-1])
		if err != nil {
			return 0, fmt.Errorf("error while reading stdin: %v", err)
		}
		if r == "r" {
			return 0, errGoBack
		}
		if r == "" {
			r = "1"
		}

		choice, err := strconv.Atoi(r)
		if err != nil || choice < 1 || choice > len(choices) {
			log.Errorf(context.TODO(), "Invalid entry. Try again or type 'r'.")
			continue
		}

		return choice - 1, nil
	}
}

func (pamClient *PAMClientBase) formChallenge(uiLayout *authd.UILayout) (
	iaResp *authd.IAResponse, err error) {
	if uiLayout.GetWait() == "true" {
		// FIXME: Add support for Ctrl+C cancellation via signalfd
		sendInfo(pamClient.pamh, "Waiting for authorization...")
		iaResp, err := pamClient.client.IsAuthorized(context.TODO(), &authd.IARequest{
			SessionId:          pamClient.sessionID,
			AuthenticationData: `{"wait": "true"}`,
		})
		if err != nil {
			return nil, err
		}

		return iaResp, nil
	}

	prompt := uiLayout.GetLabel()
	if !strings.HasSuffix(prompt, " ") {
		prompt += " "
	}

	var input string
	if uiLayout.GetEntry() == "chars" {
		input, err = requestInput(pamClient.pamh, prompt)
	} else if uiLayout.GetEntry() == "chars_password" {
		input, err = requestSecret(pamClient.pamh, prompt)
	} else {
		return nil, fmt.Errorf("Cannot handle entry of type %s", uiLayout.GetEntry())
	}

	if err != nil {
		return nil, err
	}

	if input == "r" {
		return nil, errGoBack
	}

	authData := "{}"
	if input != "" {
		// TODO: encrypt with encryptionKey
		authData = fmt.Sprintf(`{"challenge": "%s"}`, input)
	}

	// Validate challenge with Broker
	iaReq := &authd.IARequest{
		SessionId:          pamClient.sessionID,
		AuthenticationData: authData,
	}
	return pamClient.client.IsAuthorized(context.TODO(), iaReq)
}

func (pamClient *PAMClientTerminal) formChallenge(uiLayout *authd.UILayout) (
	iaResp *authd.IAResponse, err error) {
	prompt := uiLayout.GetLabel()
	if !strings.HasSuffix(prompt, " ") {
		prompt = fmt.Sprintf("%s ", prompt)
	}
	fmt.Printf("%s ('r' to cancel): ", prompt)

	type result struct {
		iaResp *authd.IAResponse
		err    error
	}
	results := make(chan result)

	waitCtx, cancelWait := context.WithCancel(context.Background())
	defer cancelWait()
	termCtx, cancelTerm := context.WithCancel(context.Background())
	defer cancelTerm()

	if uiLayout.GetWait() == "true" {
		// We can ask for an immediate authorization without challenge
		go func() {
			var err error
			iaResp, err := pamClient.client.IsAuthorized(waitCtx, &authd.IARequest{
				SessionId:          pamClient.sessionID,
				AuthenticationData: `{"wait": "true"}`,
			})

			// No more processing if entry has been filed.
			select {
			case <-waitCtx.Done():
				return
			default:
			}

			cancelTerm()

			results <- result{
				iaResp: iaResp,
				err:    err,
			}
		}()
	}

	if uiLayout.GetEntry() == "chars" || uiLayout.GetEntry() == "chars_password" {
		go func() {
			// FIXME: This should go through pam too, but we should make it not
			// blocking?
			out, err := readPasswordWithContext(int(os.Stdin.Fd()), termCtx, uiLayout.GetEntry() == "chars_password")

			// No more processing if wait IsAuthorized has been answered.
			select {
			case <-termCtx.Done():
				return
			default:
				// Immediately cancel wait goroutine, we won't care about its result.
				cancelWait()
			}

			if err != nil {
				results <- result{
					iaResp: nil,
					err:    err,
				}
			}

			authData := "{}"
			challenge := string(out)
			if challenge != "" {
				// TODO: encrypt with encryptionKey
				authData = fmt.Sprintf(`{"challenge": "%s"}`, challenge)
			}

			// Validate challenge with Broker
			iaReq := &authd.IARequest{
				SessionId:          pamClient.getSessionID(),
				AuthenticationData: authData,
			}
			iaResp, err := pamClient.getClient().IsAuthorized(context.TODO(), iaReq)
			results <- result{
				iaResp: iaResp,
				err:    err,
			}
		}()
	} else {
		fmt.Print("\n")
		// TODO: input handling to escape
	}

	r := <-results
	if r.err != nil {
		return nil, r.err
	}

	return r.iaResp, nil
}

func (pamClient *PAMClientBase) qrcodeChallenge(uiLayout *authd.UILayout) (
	iaResp *authd.IAResponse, err error) {
	l := uiLayout.GetLabel()
	var output string
	if l != "" {
		output = fmt.Sprintln(l)
	}
	qrCode, err := qrcode.New(uiLayout.GetContent(), qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("can't generate QR code: %v", err)
	}
	asciiQR := qrCode.ToSmallString(false)
	_, err = pamConv(pamClient.pamh, output+asciiQR, PamPromptInfo)
	if err != nil {
		return nil, err
	}

	iaReq := &authd.IARequest{
		SessionId:          pamClient.sessionID,
		AuthenticationData: `{"wait": "true"}`,
	}
	iaResp, err = pamClient.client.IsAuthorized(context.TODO(), iaReq)
	if err != nil {
		return nil, err
	}

	return iaResp, nil
}

func readPasswordWithContext(fd int, ctx context.Context, password bool) ([]byte, error) {
	const ioctlReadTermios = unix.TCGETS
	const ioctlWriteTermios = unix.TCSETS

	termios, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	nonblocking := false
	if err != nil {
		return nil, err
	}
	newState := *termios
	if password {
		newState.Lflag &^= unix.ECHO
	}
	newState.Lflag |= unix.ICANON | unix.ISIG
	newState.Iflag |= unix.ICRNL

	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &newState); err != nil {
		return nil, err
	}
	defer func() {
		if nonblocking {
			unix.SetNonblock(fd, false)
		}
		unix.IoctlSetTermios(fd, ioctlWriteTermios, termios)
	}()

	// Set nonblocking IO
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	nonblocking = true

	var ret []byte
	var buf [1]byte
	for {
		if ctx.Err() != nil {
			return ret, ctx.Err()
		}
		n, err := unix.Read(fd, buf[:])
		if err != nil {
			// Check for nonblocking error
			if serr, ok := err.(syscall.Errno); ok {
				if serr == 11 {
					// Add (hopefully not noticable) latency to prevent CPU hogging
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
			return ret, err
		}
		if n > 0 {
			switch buf[0] {
			case '\b':
				if len(ret) > 0 {
					ret = ret[:len(ret)-1]
				}
			case '\n':
				// Only return if r is the single character entered.
				if string(ret) == "r" {
					return nil, errGoBack
				}
				return ret, nil
			default:
				ret = append(ret, buf[0])
			}
			continue
		}
	}
}

//export pam_sm_acct_mgmt
func pam_sm_acct_mgmt(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	client, close, err := newClient(argc, argv)
	if err != nil {
		log.Debugf(context.TODO(), "%s", err)
		return C.PAM_IGNORE
	}
	defer close()

	// Get current user for broker.
	user, err := getUser(pamh, "")
	if err != nil {
		log.Infof(context.TODO(), "Can't get user: %v", err)
		return C.PAM_IGNORE
	}

	req := authd.SDBFURequest{
		SessionId: globalSessionID,
		Username:  user,
	}
	if _, err := client.SetDefaultBrokerForUser(context.TODO(), &req); err != nil {
		log.Infof(context.TODO(), "Can't set default broker for %q on session %q: %v", user, globalSessionID, err)
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

// getSocketPath returns the socket path to connect to which can be overriden manually.
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

func main() {

}
