package main_test

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/internal/testutils"
)

var daemonPath string

func TestCLIIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	_, stopped := testutils.RunDaemon(ctx, t, daemonPath, testutils.WithSocketPath("/tmp/pam-cli-tests.sock"))
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	// If vhs is installed with "go install", we need to add GOPATH to PATH.
	pathEnv := appendGoBinToPath(t)

	currentDir, err := os.Getwd()
	require.NoError(t, err, "Setup: Could not get current directory for the tests")

	tests := map[string]struct {
		tape string
	}{
		"Authenticate user successfully":               {tape: "simple_auth"},
		"Authenticate user with mfa":                   {tape: "mfa_auth"},
		"Authenticate user with form mode with button": {tape: "form_with_button"},
		"Authenticate user with qr code":               {tape: "qr_code"},
		"Authenticate user and reset password":         {tape: "mandatory_password_reset"},
		"Authenticate user and offer password reset":   {tape: "optional_password_reset"},
		"Authenticate user switching auth mode":        {tape: "switch_auth_mode"},
		"Authenticate user switching username":         {tape: "switch_username"},
		"Authenticate user switching broker":           {tape: "switch_broker"},
		"Remember last successful broker and mode":     {tape: "remember_broker_and_mode"},
		"Exit authd if local broker is selected":       {tape: "local_broker"},
		"Deny authentication if max attempts reached":  {tape: "max_attempts"},
		"Deny authentication if user does not exist":   {tape: "unexistent_user"},
		"Exit authd if user sigints":                   {tape: "sigint"},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			outDir := filepath.Dir(daemonPath)

			// #nosec:G204 - we control the command arguments in tests
			cmd := exec.Command("vhs", filepath.Join(currentDir, "testdata", "tapes", tc.tape+".tape"))
			cmd.Env = testutils.AppendCovEnv(cmd.Env)
			cmd.Env = append(cmd.Env, pathEnv)
			cmd.Dir = outDir

			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "Failed to run tape %q: %v: %s", tc.tape, err, out)

			tmp, err := os.ReadFile(filepath.Join(outDir, tc.tape+".txt"))
			require.NoError(t, err, "Could not read output file of tape %q", tc.tape)

			// We need to format the output a little bit, since the txt file can have some noise at the beginning.
			var got string
			splitTmp := strings.Split(string(tmp), "\n")
			for i, str := range splitTmp {
				if strings.HasPrefix(str, "> ./pam_authd socket=/tmp/pam-cli-tests.sock") {
					got = strings.Join(splitTmp[i:], "\n")
					break
				}
			}
			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got, "Output of tape %q does not match golden file", tc.tape)
		})
	}
}

// buildPAM builds the PAM module in a temporary directory and returns a cleanup function.
func buildPAM(execPath string) (cleanup func(), err error) {
	cmd := exec.Command("go", "build")
	if testutils.CoverDir() != "" {
		// -cover is a "positional flag", so it needs to come right after the "build" command.
		cmd.Args = append(cmd.Args, "-cover")
	}
	cmd.Args = append(cmd.Args, "-tags=pam_binary_cli", "-o", filepath.Join(execPath, "pam_authd"), "../.")
	if out, err := cmd.CombinedOutput(); err != nil {
		return func() {}, fmt.Errorf("%v: %s", err, out)
	}

	return func() { _ = os.Remove("./pam_authd") }, nil
}

// appendGoBinToPath returns the value of the GOPATH defined in go env appended to PATH.
func appendGoBinToPath(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("go", "env", "GOPATH")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Could not get GOPATH: %v: %s", err, out)

	env := os.Getenv("PATH")
	return fmt.Sprintf("PATH=%s:%s", strings.TrimSpace(string(out)+"/bin"), env)
}

func TestMain(m *testing.M) {
	testutils.InstallUpdateFlag()
	flag.Parse()

	execPath, daemonCleanup, err := testutils.BuildDaemon(true)
	if err != nil {
		log.Printf("Setup: Failed to build authd daemon: %v", err)
		os.Exit(1)
	}
	defer daemonCleanup()
	daemonPath = execPath

	pamCleanup, err := buildPAM(filepath.Dir(execPath))
	if err != nil {
		log.Printf("Setup: Failed to build PAM executable: %v", err)
		daemonCleanup()
		os.Exit(1)
	}
	defer pamCleanup()

	m.Run()
}
