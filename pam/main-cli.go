//go:build pam_binary_cli

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/msteinert/pam/v2"
	"github.com/sirupsen/logrus"
	"github.com/ubuntu/authd/pam/internal/pam_test"
)

func clearTerminal() {
	// Use ANSI codes to clear the terminal.
	// We may need this to prevent bubbletea window to hide our printed messages.
	// See: https://en.wikipedia.org/wiki/ANSI_escape_code.
	fmt.Print("\033[H\033[2J")
}

// Simulating pam on the CLI for manual testing.
func main() {
	logDir := os.Getenv("AUTHD_PAM_CLI_LOG_DIR")
	if logDir == "" {
		logDir = os.TempDir()
	}
	logPath := filepath.Join(logDir, "authd-pam-cli.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	logrus.SetOutput(f)

	module := &pamModule{}
	mTx := pam_test.NewModuleTransactionDummy(pam.ConversationFunc(
		func(style pam.Style, msg string) (string, error) {
			clearTerminal()
			switch style {
			case pam.TextInfo:
				fmt.Fprintf(os.Stderr, "PAM Info Message: %s\n", msg)
			case pam.ErrorMsg:
				fmt.Fprintf(os.Stderr, "PAM Error Message: %s\n", msg)
			default:
				return "", fmt.Errorf("PAM style %d not implemented", style)
			}
			return "", nil
		}))

	var resultMsg string
	var pamFunc pam.ModuleHandlerFunc
	action, args := os.Args[1], os.Args[2:]
	switch action {
	case "login":
		pamFunc = module.Authenticate
		resultMsg = "PAM Authenticate() for user %q"
	case "passwd":
		pamFunc = module.ChangeAuthTok
		resultMsg = "PAM ChangeAuthTok() for user %q"
	default:
		f.Close()
		panic("Unknown PAM operation: " + action)
	}

	args = append(args, "debug=true")
	pamRes := pamFunc(mTx, pam.Flags(0), args)
	user, _ := mTx.GetItem(pam.User)

	printPamResult(fmt.Sprintf(resultMsg, user), pamRes)

	// Simulate setting auth broker as default.
	printPamResult("PAM AcctMgmt()", module.AcctMgmt(mTx, pam.Flags(0), args))
}

func printPamResult(action string, result error) {
	var pamErr pam.Error
	if errors.As(result, &pamErr) {
		fmt.Printf("%s exited with error (PAM exit code: %d): %v\n", action, pamErr, result)
		return
	}
	if result != nil {
		fmt.Printf("%s exited with error: %v\n", action, result)
		return
	}
	fmt.Printf("%s exited with success\n", action)
}
