package testutils

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	bubbleWrapSupportsUnprivilegedNamespacesOnce sync.Once
	bubbleWrapSupportsUnprivilegedNamespaces     bool

	bubbleWrapNeedsSudoOnce sync.Once
	bubbleWrapNeedsSudo     bool
)

// CanRunBubbleWrapTest checks whether we can run tests running in bubblewrap or
// sip the tests otherwise.
func CanRunBubbleWrapTest(t *testing.T) {
	t.Helper()

	_, err := exec.LookPath("bwrap")
	require.NoError(t, err, "Setup: bwrap cannot be found")

	if os.Geteuid() == 0 {
		t.Log("Running as EUID 0")
		return
	}

	bubbleWrapSupportsUnprivilegedNamespacesOnce.Do(func() {
		bubbleWrapSupportsUnprivilegedNamespaces = canUseUnprivilegedUserNamespaces(t)
	})
	if bubbleWrapSupportsUnprivilegedNamespaces {
		t.Log("Can use unprivileged user namespaces")
		return
	}

	bubbleWrapNeedsSudoOnce.Do(func() {
		bubbleWrapNeedsSudo = canUseSudoNonInteractively(t)
	})
	if bubbleWrapNeedsSudo {
		t.Log("Can use sudo non-interactively")
	}

	t.Skip("Skipping test: requires root privileges or unprivileged user namespaces")
}

// RunInBubbleWrap runs the passed commands in bubble wrap sandbox.
func RunInBubbleWrap(t *testing.T, testDataPath string, args ...string) (string, error) {
	t.Helper()

	CanRunBubbleWrapTest(t)
	return runInBubbleWrap(t, bubbleWrapNeedsSudo, testDataPath, args...)
}

func runInBubbleWrap(t *testing.T, withSudo bool, testDataPath string, args ...string) (string, error) {
	t.Helper()

	var envArgs []string
	if withSudo {
		envArgs = append(envArgs, "sudo")
	}
	envArgs = append(envArgs,
		"env",
	)
	if e := CoverDirEnv(); e != "" {
		envArgs = append(envArgs, e)
	}

	etcDir := filepath.Join(testDataPath, "etc")
	var etcPerms os.FileMode = 0700
	if withSudo {
		// If running in sudo we may want to give the folder more permissions
		// not to lock out the caller.
		etcPerms = 0777
	}
	err := os.MkdirAll(etcDir, etcPerms)
	require.NoError(t, err, "Impossible to create /etc")

	bwrapPath, err := exec.LookPath("bwrap")
	require.NoError(t, err, "Impossible to find bwrap")

	bwrapArgs := []string{
		bwrapPath,
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--bind", os.TempDir(), os.TempDir(),
		"--bind", testDataPath, testDataPath,
		"--bind", etcDir, "/etc",

		// Bind relevant etc files. We go manual here, since there's no
		// need to get much more than those, while we could in theory just
		// bind everything that is in host, and excluding the ones we want
		// to override.
		"--ro-bind", "/etc/environment", "/etc/environment",
		"--ro-bind", "/etc/localtime", "/etc/localtime",
		"--ro-bind", "/etc/login.defs", "/etc/login.defs",
		"--ro-bind", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
		"--ro-bind", "/etc/passwd", "/etc/passwd",
		"--ro-bind", "/etc/shadow", "/etc/shadow",
		"--ro-bind", "/etc/subgid", "/etc/subgid",
		"--ro-bind", "/etc/sudo.conf", "/etc/sudo.conf",
		"--ro-bind", "/etc/sudoers", "/etc/sudoers",
		"--ro-bind", "/etc/timezone", "/etc/timezone",
		"--ro-bind", "/etc/pam.d", "/etc/pam.d",
		"--ro-bind", "/etc/security", "/etc/security",
	}

	if e := os.Getenv("GOCOVERDIR"); e != "" {
		bwrapArgs = append(bwrapArgs, "--bind", e, e)
	}

	if os.Geteuid() != 0 && !withSudo {
		bwrapArgs = append(bwrapArgs, "--unshare-user", "--uid", "0")
	}

	envArgs = append(envArgs, bwrapArgs...)
	args = append(envArgs, args...)

	//nolint:gosec // G204 It's fine to pass variables to exec.Command here
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = AppendCovEnv(os.Environ())

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	if IsVerbose() {
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
	}

	t.Log("Running command", strings.Join(args, " "))
	err = cmd.Run()
	output := strings.TrimSpace(b.String())

	if !IsVerbose() {
		t.Log(output)
	}
	return output, err
}

func canUseUnprivilegedUserNamespaces(t *testing.T) bool {
	t.Helper()

	if out, err := runInBubbleWrap(t, false, t.TempDir(), "/bin/true"); err != nil {
		t.Logf("Can't use unprivileged user namespaces: %v\n%s", err, out)
		return false
	}

	return true
}

func canUseSudoNonInteractively(t *testing.T) bool {
	t.Helper()

	cmd := exec.Command("sudo", "-Nnv")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("Can't use sudo non-interactively: %v\n%s", err, out)
		return false
	}

	if out, err := runInBubbleWrap(t, true, "/bin/true"); err != nil {
		t.Logf("Can't use user namespaces: %v\n%s", err, out)
		return false
	}

	return true
}
