package testutils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type daemonOptions struct {
	cachePath  string
	cacheDB    string
	socketPath string
}

// DaemonOption represents an optional function that can be used to override some of the daemon default values.
type DaemonOption func(*daemonOptions)

// WithCachePath overrides the default cache path of the daemon.
func WithCachePath(path string) DaemonOption {
	return func(o *daemonOptions) {
		o.cachePath = path
	}
}

// WithCacheDB overrides the default cache database of the daemon.
func WithCacheDB(db string) DaemonOption {
	return func(o *daemonOptions) {
		o.cacheDB = db
	}
}

// WithSocketPath overrides the default socket path of the daemon.
func WithSocketPath(path string) DaemonOption {
	return func(o *daemonOptions) {
		o.socketPath = path
	}
}

// RunDaemon runs the daemon in a separate process and returns the socket path and a channel that will be closed when
// the daemon stops.
func RunDaemon(ctx context.Context, t *testing.T, execPath string, args ...DaemonOption) (socketPath string, stopped chan struct{}) {
	t.Helper()

	opts := &daemonOptions{}
	for _, opt := range args {
		opt(opts)
	}

	// Socket name has a maximum size, so we can't use t.TempDir() directly.
	tempDir, err := os.MkdirTemp("", "authd-daemon4tests")
	require.NoError(t, err, "Setup: failed to create temp dir for tests")
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	if opts.cachePath == "" {
		opts.cachePath = filepath.Join(tempDir, "cache")
		require.NoError(t, os.MkdirAll(opts.cachePath, 0700), "Setup: failed to create cache dir")
	}

	if opts.cacheDB != "" {
		CreateDBFromYAML(t, filepath.Join("testdata", "db", opts.cacheDB+".db.yaml"), opts.cachePath)
	}

	if opts.socketPath == "" {
		opts.socketPath = filepath.Join(tempDir, "authd.socket")
	}

	config := fmt.Sprintf(`
verbosity: 2
paths:
  cache: %s
  socket: %s
`, opts.cachePath, opts.socketPath)

	configPath := filepath.Join(tempDir, "testconfig.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0600), "Setup: failed to create config file for tests")

	// #nosec:G204 - we control the command arguments in tests
	cmd := exec.Command(execPath, "-c", configPath)
	cmd.Stderr = os.Stderr
	cmd.Env = AppendCovEnv(os.Environ())

	stopped = make(chan struct{})
	go func() {
		require.NoError(t, cmd.Start(), "Setup: daemon should start with no error")
		<-ctx.Done()
		// The daemon can trigger some background tasks so, in order to stop it gracefully, we need to send either
		// SIGTERM or SIGINT to tell it that it's time to cleanup and stop.
		require.NoError(t, cmd.Process.Signal(os.Signal(syscall.SIGTERM)), "Teardown: Failed to send signal to stop daemon")
		require.NoError(t, cmd.Wait(), "Teardown: daemon should stop with no error")
		close(stopped)
	}()

	// Give some time for the daemon to start.
	time.Sleep(time.Second)

	return opts.socketPath, stopped
}

// BuildDaemon builds the daemon executable and returns the binary path.
func BuildDaemon(brokerNeeded bool) (execPath string, cleanup func(), err error) {
	projectRoot := ProjectRoot()

	tempDir, err := os.MkdirTemp("", "authd-tests-daemon")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	cleanup = func() { os.RemoveAll(tempDir) }

	execPath = filepath.Join(tempDir, "authd")
	cmd := exec.Command("go", "build")
	cmd.Dir = projectRoot
	if CoverDir() != "" {
		// -cover is a "positional flag", so it needs to come right after the "build" command.
		cmd.Args = append(cmd.Args, "-cover")
	}
	if brokerNeeded {
		cmd.Args = append(cmd.Args, "-tags=withexamplebroker")
	}
	cmd.Args = append(cmd.Args, "-o", execPath, "./cmd/authd")

	if err := cmd.Run(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to build daemon: %w", err)
	}

	return execPath, cleanup, err
}
