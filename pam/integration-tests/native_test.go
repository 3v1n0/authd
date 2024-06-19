package main_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	permissionstestutils "github.com/ubuntu/authd/internal/services/permissions/testutils"
	"github.com/ubuntu/authd/internal/testutils"
	localgroupstestutils "github.com/ubuntu/authd/internal/users/localgroups/testutils"
)

func TestNativeAuthenticate(t *testing.T) {
	t.Parallel()

	// Due to external dependencies such as `vhs`, we can't run the tests in some environments (like LP builders), as we
	// can't install the dependencies there. So we need to be able to skip these tests on-demand.
	if os.Getenv("AUTHD_SKIP_EXTERNAL_DEPENDENT_TESTS") != "" {
		t.Skip("Skipping tests with external dependencies as requested")
	}

	// If vhs is installed with "go install", we need to add GOPATH to PATH.
	pathEnv := prependBinToPath(t)

	currentDir, err := os.Getwd()
	require.NoError(t, err, "Setup: Could not get current directory for the tests")

	clientPath := t.TempDir()
	pamCleanup, err := buildPAMTestClient(clientPath)
	require.NoError(t, err, "Setup: Failed to build PAM executable")
	t.Cleanup(pamCleanup)

	cliEnv := []string{
		fmt.Sprintf("AUTHD_PAM_EXEC_MODULE=%s", buildExecModule(t)),
		fmt.Sprintf("AUTHD_PAM_CLI_PATH=%s", buildPAMClient(t)),
	}

	tests := map[string]struct {
		tape string

		currentUserNotRoot bool
	}{
		"Authenticate user successfully":                      {tape: "simple_auth"},
		"Authenticate user successfully with preset user":     {tape: "simple_auth_with_preset_user"},
		"Authenticate user with mfa":                          {tape: "mfa_auth"},
		"Authenticate user with form mode with button":        {tape: "form_with_button"},
		"Authenticate user with qr code":                      {tape: "qr_code"},
		"Authenticate user and reset password":                {tape: "mandatory_password_reset"},
		"Authenticate user and reset password with mismatch":  {tape: "mandatory_password_reset_with_mismatch"},
		"Authenticate user and offer password reset":          {tape: "optional_password_reset_skip"},
		"Authenticate user and accept password reset":         {tape: "optional_password_reset_do"},
		"Authenticate user switching auth mode":               {tape: "switch_auth_mode"},
		"Authenticate user switching username":                {tape: "switch_username"},
		"Authenticate user switching to local broker":         {tape: "switch_broker"},
		"Authenticate user and add it to local group":         {tape: "local_group"},
		"Authenticate with warnings on unsupported arguments": {tape: "simple_auth_with_unsupported_args"},

		"Remember last successful broker and mode":      {tape: "remember_broker_and_mode"},
		"Autoselect local broker for local user":        {tape: "local_user"},
		"Autoselect local broker for local user preset": {tape: "local_user_preset"},

		"Deny authentication if current user is not considered as root": {tape: "not_root", currentUserNotRoot: true},

		"Deny authentication if max attempts reached":   {tape: "max_attempts"},
		"Deny authentication if user does not exist":    {tape: "unexistent_user"},
		"Deny authentication if usernames do not match": {tape: "mismatch_username"},

		"Exit authd if local broker is selected": {tape: "local_broker"},
		// FIXME: While this works now, it requires proper handling via signal_fd
		"Exit authd if user sigints": {tape: "sigint"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			outDir := t.TempDir()
			err := os.Symlink(filepath.Join(clientPath, "pam_authd"),
				filepath.Join(outDir, "pam_authd"))
			require.NoError(t, err, "Setup: symlinking the pam client")

			cliLog := prepareCLILogging(t)
			t.Cleanup(func() {
				saveArtifactsForDebug(t, []string{
					filepath.Join(outDir, tc.tape+".gif"),
					filepath.Join(outDir, tc.tape+".txt"),
					cliLog,
				})
			})

			gpasswdOutput := filepath.Join(outDir, "gpasswd.output")
			groupsFile := filepath.Join(testutils.TestFamilyPath(t), "gpasswd.group")
			socketPath := runAuthd(t, gpasswdOutput, groupsFile, !tc.currentUserNotRoot)

			const socketPathEnv = "AUTHD_TESTS_CLI_AUTHENTICATE_TESTS_SOCK"
			// #nosec:G204 - we control the command arguments in tests
			cmd := exec.Command("env", "vhs", filepath.Join(currentDir, "testdata", "native-tapes", tc.tape+".tape"))
			cmd.Env = append(testutils.AppendCovEnv(cmd.Env), cliEnv...)
			cmd.Env = append(cmd.Env,
				pathEnv,
				fmt.Sprintf("%s=%s", socketPathEnv, socketPath),
				fmt.Sprintf("AUTHD_PAM_CLI_LOG_DIR=%s", filepath.Dir(cliLog)),
				fmt.Sprintf("AUTHD_PAM_CLI_TEST_NAME=%s", t.Name()),
				"AUTHD_PAM_CLI_SUPPORTS_CONVERSATION=1",
			)
			cmd.Dir = outDir

			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "Failed to run tape %q: %v: %s", tc.tape, err, out)

			tmp, err := os.ReadFile(filepath.Join(outDir, tc.tape+".txt"))
			require.NoError(t, err, "Could not read output file of tape %q", tc.tape)

			// We need to format the output a little bit, since the txt file can have some noise at the beginning.
			got := string(tmp)
			splitTmp := strings.Split(got, "\n")
			for i, str := range splitTmp {
				if strings.Contains(str, " ./pam_authd login socket=$") {
					got = strings.Join(splitTmp[i:], "\n")
					break
				}
			}
			got = permissionstestutils.IdempotentPermissionError(got)
			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got, "Output of tape %q does not match golden file", tc.tape)

			localgroupstestutils.RequireGPasswdOutput(t, gpasswdOutput, testutils.GoldenPath(t)+".gpasswd_out")
		})
	}
}
