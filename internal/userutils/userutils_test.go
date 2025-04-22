//go:build !bubblewrap_test

package userutils_test

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/internal/fileutils"
	"github.com/ubuntu/authd/internal/testutils"
	"github.com/ubuntu/authd/internal/userutils"
)

func TestUserUtilsInBubbleWrap(t *testing.T) {
	t.Parallel()

	testutils.CanRunBubbleWrapTest(t)

	// Create a binary for the bubbletea tests.
	mainTestBinary := compileTestBinary(t)

	//nolint:gosec // G204 we define the parameters here.
	testsList, err := exec.Command(mainTestBinary, "-test.list", ".*").CombinedOutput()
	require.NoError(t, err, "Setup: Checking for test: %s", testsList)
	testsListStr := strings.TrimSpace(string(testsList))
	require.NotEmpty(t, testsListStr, "Setup: test not found", testsListStr)

	lockerBinary := compileLockerBinary(t)

	for _, name := range strings.Split(testsListStr, "\n") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testEnv := []string{}

			// Create a temporary folder for tests.
			testDataPath := t.TempDir()
			testBinary := filepath.Join(testDataPath, filepath.Base(mainTestBinary))
			err := fileutils.CopyFile(mainTestBinary, testBinary)
			require.NoError(t, err, "Setup: Copying test binary to local test path")

			testLockerBinary := filepath.Join(testDataPath, filepath.Base(lockerBinary))
			err = fileutils.CopyFile(lockerBinary, testLockerBinary)
			require.NoError(t, err, "Setup: Copying locker binary to local test path")
			testEnv = append(testEnv, "AUTHD_TESTS_PASSWD_LOCKER_UTILITY="+testLockerBinary)

			nameRegex := fmt.Sprintf("^%s$", regexp.QuoteMeta(name))
			//nolint:gosec // G204 we define the parameters here.
			testsList, err := exec.Command(testBinary, "-test.list", nameRegex).CombinedOutput()
			require.NoError(t, err, "Setup: Checking for test: %s", testsList)
			testsListStr := strings.TrimSpace(string(testsList))
			require.NotEmpty(t, testsListStr, "Setup: %q test not found", name)
			require.Len(t, strings.Split(testsListStr, "\n"), 1,
				"Setup: Too many tests defined for %s", testsListStr)

			bubbleWrapArgs := []string{testBinary, "-test.run", nameRegex}
			if testutils.IsVerbose() {
				bubbleWrapArgs = append(bubbleWrapArgs, "-test.v")
			}
			if c := testutils.CoverDirForTests(); c != "" {
				bubbleWrapArgs = append(bubbleWrapArgs, "-test.gocoverdir="+c)
			}
			out, err := testutils.RunInBubbleWrapWithEnv(t, testDataPath, testEnv,
				bubbleWrapArgs...)
			require.NoError(t, err, "Running test: %s\n%s", name, out)
		})
	}
}

func compileTestBinary(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("go", "test")
	// These are positional arguments.
	if testutils.CoverDirForTests() != "" {
		cmd.Args = append(cmd.Args, "-cover")
	}
	if testutils.IsAsan() {
		cmd.Args = append(cmd.Args, "-asan")
	}
	if testutils.IsRace() {
		cmd.Args = append(cmd.Args, "-race")
	}

	testBinary := filepath.Join(t.TempDir(), "test-binary")
	cmd.Args = append(cmd.Args, []string{
		"-tags", "bubblewrap_test", "-c", "-o", testBinary,
	}...)

	t.Logf("Compiling test binary: %s", strings.Join(cmd.Args, " "))
	compileOut, err := cmd.CombinedOutput()
	require.NoError(t, err, "Setup: Cannot compile test file: %s", compileOut)

	return testBinary
}

func compileLockerBinary(t *testing.T) string {
	t.Helper()

	testLocker := filepath.Join(t.TempDir(), "test-locker")
	cmd := exec.Command("go", "build", "-C", "testlocker")
	cmd.Args = append(cmd.Args, []string{
		"-tags", "test_locker", "-o", testLocker,
	}...)

	t.Logf("Compiling locker binary: %s", strings.Join(cmd.Args, " "))
	compileOut, err := cmd.CombinedOutput()
	require.NoError(t, err, "Setup: Cannot compile locker file: %s", compileOut)

	return testLocker
}

func TestUserUtilsPasswordLockingOverride(t *testing.T) {
	// This cannot be parallel.

	userutils.OverrideShadowPasswordLocking()
	t.Cleanup(userutils.RestoreShadowPasswordLocking)

	err := userutils.WriteLockShadowPassword()
	require.NoError(t, err, "Locking should be allowed")

	err = userutils.WriteLockShadowPassword()
	require.ErrorIs(t, err, userutils.ErrLock, "Locking again should not be allowed")

	err = userutils.WriteUnlockShadowPassword()
	require.NoError(t, err, "Unlocking should be allowed")

	err = userutils.WriteUnlockShadowPassword()
	require.ErrorIs(t, err, userutils.ErrUnlock, "Unlocking unlocked should not be allowed")
}
