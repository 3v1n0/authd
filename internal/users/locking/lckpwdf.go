package userslocking

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ubuntu/decorate"
)

const (
	defaultEtcPasswdLockFilename = ".pwd.lock"
	defaultEtcPasswdLockPath     = "/etc/" + defaultEtcPasswdLockFilename
)

var (
	etcPasswdLockPath = defaultEtcPasswdLockPath

	mu         sync.Mutex
	lockedFile *os.File
	/* Use atomic with a Lckpwfd struct that is initialized to a null ptr and filled in case */
)

// lckpwdf is a simpler native implementation of glibc one, however we follow
// the systemd indication, so we ignore doing the per-database locks (as they
// are racy), and we don't rely on alarms.
func lckpwdf() (err error) {
	defer decorate.OnError(&err, "lckpwdf")

	mu.Lock()
	defer mu.Unlock()

	if lockedFile != nil {
		return fmt.Errorf("%w: we already have the lock", ErrLock)
	}

	//nolint:gosec // G302 Permissions 0755 are valid for /etc
	if err := os.MkdirAll(filepath.Dir(etcPasswdLockPath), 0755); err != nil {
		return fmt.Errorf("%w: %w", ErrLock, err)
	}

	file, err := os.OpenFile(etcPasswdLockPath, os.O_WRONLY|os.O_CREATE|
		syscall.O_CLOEXEC|syscall.O_NOCTTY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLock, err)
	}

	errChan := make(chan error)
	go func() {
		for {
			err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &syscall.Flock_t{
				Type:   syscall.F_WRLCK,
				Whence: io.SeekStart, // Just as SEEK_SET
			})

			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				<-time.After(16 * time.Millisecond)
				continue
			}

			if err != nil {
				errChan <- fmt.Errorf("%w: %w", ErrLock, err)
			}

			errChan <- nil
			break
		}
	}()

	select {
	case err = <-errChan:
	case <-time.After(maxWait):
		_ = file.Close()
		return fmt.Errorf("%w: got no lock in time", ErrLockTimeout)
	}

	if err != nil {
		_ = file.Close()
		return fmt.Errorf("%w: %w", ErrLock, err)
	}

	lockedFile = file
	return nil
}

func ulckpwdf() (err error) {
	mu.Lock()
	defer mu.Unlock()

	if lockedFile == nil {
		return fmt.Errorf("%w: we do not have any lock", ErrUnlock)
	}

	if err = lockedFile.Close(); err != nil {
		return fmt.Errorf("%w: %w", ErrUnlock, err)
	}

	lockedFile = nil
	return nil
}
