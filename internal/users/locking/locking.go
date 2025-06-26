// Package userslocking implements locking of the local user and group files
// (/etc/passwd, /etc/groups, /etc/shadow, /etc/gshadow) via the libc lckpwdf()
// function.
//
// It is recommended by systemd to hold this lock when picking a new UID/GID to
// avoid races, even if the new user/group is not added to the local user/group
// files. See https://github.com/systemd/systemd/blob/main/docs/UIDS-GIDS.md.
package userslocking

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	writeLockImpl   = writeLock
	writeUnlockImpl = writeUnlock

	writeLocksCount   uint64
	writeLocksCountMu sync.RWMutex

	// maxWait is the maximum wait time for a lock to happen.
	// We mimic the libc behavior, in case we don't get SIGALRM'ed.
	maxWait = 16 * time.Second
)

var (
	// ErrLock is the error when locking the database fails.
	ErrLock = errors.New("failed to lock the shadow password database")

	// ErrUnlock is the error when unlocking the database fails.
	ErrUnlock = errors.New("failed to unlock the shadow password database")

	// ErrLockTimeout is the error when unlocking the database fails because of timeout.
	ErrLockTimeout = fmt.Errorf("%w: timeout", ErrLock)
)

func writeLockInternal() error {
	done := make(chan error)
	go func() {
		done <- writeLockImpl()
	}()

	select {
	// lckpwdf when called from cgo doesn't behave exactly the same, likely
	// because alarms are handled by go runtime, so do it manually here by
	// failing if "lock not obtained within 15 seconds" as per lckpwdf.3.
	// Keep this in sync with what lckpwdf does, adding an extra second.
	case <-time.After(maxWait):
		return ErrLockTimeout
	case err := <-done:
		return err
	}
}

// WriteRecLock locks the system's user database for writing via the libc
// lckpwdf() function. While the lock is held, all other processes trying to
// lock the database via lckpwdf() will block until the lock is released or
// the lckpwdf() timeout (15 seconds) is reached.
//
// This function is recursive, it can be called multiple times without deadlocking -
// even by different goroutines - the lckpwdf() function is only called if the
// reference count is 0, else it just increments the reference count.
//
// WriteRecUnlock must be called the same number of times as WriteRecLock to
// release the lock.
func WriteRecLock() error {
	writeLocksCountMu.Lock()
	defer writeLocksCountMu.Unlock()

	if writeLocksCount == 0 {
		if err := writeLockInternal(); err != nil {
			return err
		}
	}

	writeLocksCount++
	return nil
}

// WriteRecUnlock decreases the reference count of the lock acquired by WriteRecLock.
// If the reference count reaches 0, it releases the lock by calling the libc
// ulckpwdf() function.
func WriteRecUnlock() error {
	writeLocksCountMu.Lock()
	defer writeLocksCountMu.Unlock()

	if writeLocksCount == 0 {
		return fmt.Errorf("%w: no locks found", ErrUnlock)
	}

	if writeLocksCount > 1 {
		writeLocksCount--
		return nil
	}

	if err := writeUnlockImpl(); err != nil {
		return err
	}

	writeLocksCount--
	return nil
}
