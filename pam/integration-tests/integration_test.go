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

func TestIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	_, stopped := testutils.RunDaemon(ctx, t, daemonPath, testutils.WithSocketPath("/tmp/authd.sock"))
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	tests := map[string]struct {
		tape string
	}{
		"Authenticate user successfully":               {tape: "simple_auth"},
		"Authenticate user with mfa":                   {tape: "mfa_auth"},
		"Authenticate user with form mode with button": {tape: "form_with_button"},
		"Authenticate user and reset password":         {tape: "mandatory_password_reset"},
		"Authenticate user and offer password reset":   {tape: "optional_password_reset"},
		"Authenticate user switching auth mode":        {tape: "switch_auth_mode"},
		"Remember last successful auth mode":           {tape: "remember_auth_mode"},
		"Exit authd if local broker is selected":       {tape: "local_broker"},
		"Deny authentication if max attempts reached":  {tape: "max_attempts"},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// #nosec:G204 - we control the command arguments in tests
			cmd := exec.Command("vhs", filepath.Join("testdata", "tapes", tc.tape+".tape"))
			cmd.Env = testutils.AppendCovEnv(os.Environ())

			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "Failed to run tape %q: %v: %s", tc.tape, err, out)
			t.Cleanup(func() {
				_ = os.Remove(tc.tape + ".txt")
				_ = os.Remove(tc.tape + ".gif")
			})

			tmp, err := os.ReadFile(tc.tape + ".txt")
			require.NoError(t, err, "Could not read output file of tape %q", tc.tape)
			// We need to format the output a little bit, since the txt file can have some noise at the beginning.
			var got string
			splitTmp := strings.Split(string(tmp), "\n")
			for i, str := range splitTmp {
				if strings.HasPrefix(str, "> ./pam_authd socket=/tmp/authd.sock") {
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
func buildPAM() (cleanup func(), err error) {
	cmd := exec.Command("go", "build")
	if testutils.CoverDir() != "" {
		// -cover is a "positional flag", so it needs to come right after the "build" command.
		cmd.Args = append(cmd.Args, "-cover")
	}
	cmd.Args = append(cmd.Args, "-o", "./pam_authd", "../.")
	if out, err := cmd.CombinedOutput(); err != nil {
		return func() {}, fmt.Errorf("%v: %s", err, out)
	}

	return func() { os.Remove("./pam_authd") }, nil
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

	pamCleanup, err := buildPAM()
	if err != nil {
		log.Printf("Setup: Failed to build PAM executable: %v", err)
		daemonCleanup()
		os.Exit(1)
	}
	defer pamCleanup()

	m.Run()
}
