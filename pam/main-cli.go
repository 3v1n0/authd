//go:build pam_binary_cli

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd/internal/testutils"
	"github.com/ubuntu/authd/pam/internal/pam_test"
)

// Simulating pam on the CLI for manual testing.
func main() {
	logDir := os.Getenv("AUTHD_PAM_CLI_LOG_DIR")
	execModule := os.Getenv("AUTHD_PAM_EXEC_MODULE")
	cliPath := os.Getenv("AUTHD_PAM_CLI_PATH")

	tmpDir, err := os.MkdirTemp(os.TempDir(), "pam-cli-tester-")
	if err != nil {
		log.Fatalf("Can't create temporary dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if _, err := os.Stat(execModule); err != nil {
		execModule, err = buildExecModule(tmpDir)
		if err != nil {
			log.Fatalf("Module build failed: %v", err)
		}
	}

	if _, err := os.Stat(cliPath); err != nil {
		cliPath, err = buildClient(tmpDir)
		if err != nil {
			log.Fatalf("Client build failed: %v", err)
		}
	}

	defaultArgs := []string{cliPath, "debug=true"}
	if logDir != "" {
		logPath := filepath.Join(logDir, "authd-pam-cli.log")
		defaultArgs = append(defaultArgs, "logfile="+logPath)
	}

	if coverDir := os.Getenv("GOCOVERDIR"); coverDir != "" {
		defaultArgs = append(defaultArgs, "--env", fmt.Sprintf("GOCOVERDIR=%s", coverDir))
	}

	if len(os.Args) < 2 {
		log.Fatalf("Not enough arguments")
	}

	action, args := os.Args[1], os.Args[2:]
	args = append(defaultArgs, args...)

	serviceFile, err := pam_test.CreateService(tmpDir, "authd-cli", []pam_test.ServiceLine{
		{Action: pam_test.Auth, Control: pam_test.SufficientRequisite, Module: execModule, Args: args},
		{Action: pam_test.Auth, Control: pam_test.Sufficient, Module: pam_test.Ignore.String()},
		{Action: pam_test.Account, Control: pam_test.SufficientRequisite, Module: execModule, Args: args},
		{Action: pam_test.Account, Control: pam_test.Sufficient, Module: pam_test.Ignore.String()},
		{Action: pam_test.Password, Control: pam_test.SufficientRequisite, Module: execModule, Args: args},
		{Action: pam_test.Password, Control: pam_test.Sufficient, Module: pam_test.Ignore.String()},
	})
	if err != nil {
		log.Fatalf("Can't create service file %s: %v", serviceFile, err)
	}

	tx, err := pam.StartConfDir(filepath.Base(serviceFile), "", pam.ConversationFunc(
		func(style pam.Style, msg string) (string, error) {
			switch style {
			case pam.TextInfo:
				fmt.Fprintf(os.Stderr, "PAM Info Message: %s\n", msg)
			case pam.ErrorMsg:
				fmt.Fprintf(os.Stderr, "PAM Error Message: %s\n", msg)
			default:
				return "", fmt.Errorf("PAM style %d not implemented", style)
			}
			return "", nil
		}), filepath.Dir(serviceFile))
	if err != nil {
		log.Fatalf("Impossible to start transaction %v: %v", cliPath, err)
	}
	defer tx.End()

	var resultMsg string
	var pamFunc func(pam.Flags) error
	switch action {
	case "login":
		pamFunc = tx.Authenticate
		resultMsg = "PAM Authenticate() for user %q"
	case "passwd":
		pamFunc = tx.ChangeAuthTok
		resultMsg = "PAM ChangeAuthTok() for user %q"
	default:
		panic("Unknown PAM operation: " + action)
	}

	pamRes := pamFunc(pam.Flags(0))
	user, _ := tx.GetItem(pam.User)

	printPamResult(fmt.Sprintf(resultMsg, user), pamRes)

	// Simulate setting auth broker as default.
	printPamResult("PAM AcctMgmt()", tx.AcctMgmt(pam.Flags(0)))
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

func getPkgConfigFlags(args []string) ([]string, error) {
	out, err := exec.Command("pkg-config", args...).CombinedOutput()
	if err != nil {
		fmt.Errorf("can't get pkg-config dependencies: %w: %s", err, out)
	}
	return strings.Split(strings.TrimSpace(string(out)), " "), nil
}

func buildExecModule(path string) (string, error) {
	execModule := filepath.Join(path, "pam_exec.so")
	deps, err := getPkgConfigFlags([]string{"--cflags", "--libs", "gio-2.0", "gio-unix-2.0"})
	if err != nil {
		return "", err
	}
	cmd := exec.Command("cc", "pam/go-exec/module.c", "-o", execModule,
		"-shared", "-fPIC")
	cmd.Args = append(cmd.Args, deps...)
	cmd.Dir = testutils.ProjectRoot()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("can't compile exec module %s: %w\n%s", execModule, err, out)
	}

	return execModule, nil
}

func buildClient(path string) (string, error) {
	cliPath := filepath.Join(path, "exec-client")
	cmd := exec.Command("go", "build", "-C", "pam", "-o", cliPath)
	cmd.Dir = testutils.ProjectRoot()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("can't compile client %s: %v\n%s", cliPath, err, out)
	}
	return cliPath, nil
}
