// Package localentries provides functions to access the local user and group database.
//
//nolint:dupl // This it not a duplicate of getpwent_c.go
package localentries

/*
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ubuntu/authd/internal/errno"
	"github.com/ubuntu/authd/internal/users/types"
)

var getgrentMu sync.Mutex

func getGroupEntry() (*C.struct_group, error) {
	errno.Lock()
	defer errno.Unlock()

	cGroup := C.getgrent()
	if cGroup != nil {
		return cGroup, nil
	}

	err := errno.Get()
	// It's not documented in the man page, but apparently getgrent sets errno to ENOENT when there are no more
	// entries in the group database.
	if errors.Is(err, errno.ErrNoEnt) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getgrent: %v", err)
	}
	return cGroup, nil
}

// GetGroupEntries returns all group entries.
func GetGroupEntries() ([]types.GroupEntry, error) {
	// This function repeatedly calls getgrent, which iterates over the records in the group database.
	// Use a mutex to avoid that parallel calls to this function interfere with each other.
	getgrentMu.Lock()
	defer getgrentMu.Unlock()

	C.setgrent()
	defer C.endgrent()

	var entries []types.GroupEntry
	for {
		cGroup, err := getGroupEntry()
		if err != nil {
			return nil, err
		}
		if cGroup == nil {
			// No more entries in the group database.
			break
		}

		entries = append(entries, types.GroupEntry{
			Name:   C.GoString(cGroup.gr_name),
			GID:    uint32(cGroup.gr_gid),
			Passwd: C.GoString(cGroup.gr_passwd),
		})
	}

	return entries, nil
}

// ErrGroupNotFound is returned when a group is not found.
var ErrGroupNotFound = errors.New("group not found")

// GetGroupByName returns the group with the given name.
func GetGroupByName(name string) (types.GroupEntry, error) {
	errno.Lock()
	defer errno.Unlock()

	cGroup := C.getgrnam(C.CString(name))
	if cGroup == nil {
		err := errno.Get()
		if err == nil ||
			errors.Is(err, errno.ErrNoEnt) ||
			errors.Is(err, errno.ErrSrch) ||
			errors.Is(err, errno.ErrBadf) ||
			errors.Is(err, errno.ErrPerm) {
			return types.GroupEntry{}, ErrGroupNotFound
		}
		return types.GroupEntry{}, fmt.Errorf("getgrnam: %v", err)
	}

	return types.GroupEntry{
		Name: C.GoString(cGroup.gr_name),
		GID:  uint32(cGroup.gr_gid),
	}, nil
}
