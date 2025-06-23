// Package localentries provides functions to retrieve passwd and group entries and to update the groups of a user.
package localentries

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/ubuntu/authd/internal/fileutils"
	"github.com/ubuntu/authd/internal/sliceutils"
	"github.com/ubuntu/authd/internal/testsdetection"
	userslocking "github.com/ubuntu/authd/internal/users/locking"
	"github.com/ubuntu/authd/internal/users/types"
	"github.com/ubuntu/authd/log"
	"github.com/ubuntu/decorate"
)

// GroupFile is the default local group file.
const GroupFile = "/etc/group"

var defaultOptions = options{
	groupInputPath:  GroupFile,
	groupOutputPath: GroupFile,
}

type options struct {
	groupInputPath  string
	groupOutputPath string
}

// Option represents an optional function to override UpdateLocalGroups default values.
type Option func(*options)

type lockedGroups struct {
	mu            sync.RWMutex
	refCount      uint64
	options       options
	currentGroups []types.GroupEntry
}

// defaultLockedGroupsInstance is used as the instance for locked groups when
// no test options are provided.
var defaultLockedGroupsInstance = &lockedGroups{}

// GetLockedGroups gets a [lockedGroups] instance that allows to perform operations on
// user groups that require users locking, and a cleanup function to release it.
//
//nolint:revive,nolintlint  // [lockedGroups] is not a type we want to be able to use outside of this package
func GetLockedGroups(args ...Option) (locked *lockedGroups, cleanup func() error, err error) {
	defer decorate.OnError(&err, "could not lock local groups")

	if err := userslocking.WriteRecLock(); err != nil {
		return nil, nil, err
	}

	cleanupUnlocked := func() error {
		if locked.refCount == 0 {
			return fmt.Errorf("locked groups were already unlocked")
		}

		locked.refCount--
		if locked.refCount == 0 {
			locked.currentGroups = nil
		}
		return userslocking.WriteRecUnlock()
	}

	cleanup = func() error {
		locked.mu.Lock()
		defer locked.mu.Unlock()

		return cleanupUnlocked()
	}

	locked = defaultLockedGroupsInstance
	testingMode := len(args) != 0

	if testingMode {
		testsdetection.MustBeTesting()
		locked = &lockedGroups{}
	}

	locked.mu.Lock()
	defer locked.mu.Unlock()

	locked.refCount++
	if locked.refCount > 1 {
		return locked, cleanup, nil
	}

	opts := defaultOptions
	for _, arg := range args {
		arg(&opts)
	}

	locked.options = opts
	locked.currentGroups, err = parseLocalGroups(opts.groupInputPath)
	if err != nil {
		return nil, nil, errors.Join(err, cleanupUnlocked())
	}

	return locked, cleanup, nil
}

func (l *lockedGroups) mustLock() (cleanup func()) {
	l.mu.Lock()
	cleanup = l.mu.Unlock

	if l.refCount == 0 {
		defer cleanup()
		panic("locked groups are not locked!")
	}

	return cleanup
}

// Update synchronizes for the given user the local group list with the current group list from UserInfo.
func (l *lockedGroups) Update(username string, newGroups []string, oldGroups []string) (err error) {
	log.Debugf(context.TODO(), "Updating local groups for user %q, new groups: %v, old groups: %v", username, newGroups, oldGroups)
	defer decorate.OnError(&err, "could not update local groups for user %q", username)

	unlock := l.mustLock()
	defer unlock()

	allGroups := types.DeepCopyGroupEntries(l.currentGroups)
	userGroups := l.userLocalGroups(username)
	currentGroupsNames := sliceutils.Map(userGroups, func(g types.GroupEntry) string {
		return g.Name
	})

	groupsToAdd := sliceutils.Difference(newGroups, currentGroupsNames)
	log.Debugf(context.TODO(), "Adding %q to local groups: %v", username, groupsToAdd)
	groupsToRemove := sliceutils.Difference(oldGroups, newGroups)
	// Only remove user from groups which they are part of
	groupsToRemove = sliceutils.Intersection(groupsToRemove, currentGroupsNames)
	log.Debugf(context.TODO(), "Removing %q from local groups: %v", username, groupsToRemove)

	if len(groupsToRemove) == 0 && len(groupsToAdd) == 0 {
		return nil
	}

	getCurrentGroupByName := func(name string) *types.GroupEntry {
		idx := slices.IndexFunc(allGroups, func(g types.GroupEntry) bool { return g.Name == name })
		if idx == -1 {
			return nil
		}
		return &allGroups[idx]
	}

	usersCompareFunc := func(u string) bool { return u == username }
	for _, g := range groupsToRemove {
		group := getCurrentGroupByName(g)
		if group == nil {
			continue
		}
		group.Users = slices.DeleteFunc(group.Users, usersCompareFunc)
	}
	for _, g := range groupsToAdd {
		group := getCurrentGroupByName(g)
		if group == nil {
			continue
		}
		group.Users = append(group.Users, username)
	}

	return l.saveLocalGroups(allGroups)
}

func parseLocalGroups(groupPath string) (groups []types.GroupEntry, err error) {
	defer decorate.OnError(&err, "could not fetch existing local group")

	log.Debugf(context.Background(), "Reading groups from %q", groupPath)

	f, err := os.Open(groupPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Format of a line composing the group file is:
	// group_name:password:group_id:user1,…,usern
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t == "" {
			continue
		}
		elems := strings.Split(t, ":")
		if len(elems) != 4 {
			return nil, fmt.Errorf("malformed entry in group file (should have 4 separators, got %d): %q", len(elems), t)
		}

		name, passwd, gidValue, usersValue := elems[0], elems[1], elems[2], elems[3]

		gid, err := strconv.ParseUint(gidValue, 10, 0)
		if err != nil || gid > math.MaxUint32 {
			return nil, fmt.Errorf("failed parsing entry %q, unexpected GID value", t)
		}

		var users []string
		if usersValue != "" {
			users = strings.Split(usersValue, ",")
		}

		groups = append(groups, types.GroupEntry{
			Name:   name,
			Passwd: passwd,
			GID:    uint32(gid),
			Users:  users,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if err := types.ValidateGroupEntries(groups); err != nil {
		return nil, err
	}

	return groups, nil
}

func groupFileTemporaryPath(groupPath string) string {
	return fmt.Sprintf("%s+", groupPath)
}

func groupFileBackupPath(groupPath string) string {
	return fmt.Sprintf("%s-", groupPath)
}

func formatGroupEntries(groups []types.GroupEntry) string {
	groupLines := sliceutils.Map(groups, func(group types.GroupEntry) string {
		return strings.Join([]string{
			group.Name,
			group.Passwd,
			fmt.Sprint(group.GID),
			strings.Join(group.Users, ","),
		}, ":")
	})

	// Add final new line to the group file.
	groupLines = append(groupLines, "")

	return strings.Join(groupLines, "\n")
}

func (l *lockedGroups) saveLocalGroups(groups []types.GroupEntry) (err error) {
	inputPath := l.options.groupInputPath
	groupPath := l.options.groupOutputPath

	defer decorate.OnError(&err, "could not write local groups to %q", groupPath)

	if err := types.ValidateGroupEntries(groups); err != nil {
		return err
	}

	backupPath := groupFileBackupPath(groupPath)
	oldBackup := ""
	groupsEntries := formatGroupEntries(groups)

	log.Debugf(context.TODO(), "Saving group entries %#v to %q", groups, groupPath)
	if len(groupsEntries) > 0 {
		log.Debugf(context.TODO(), "Group file content:\n%s", groupsEntries)
	}

	if tmpDir, err := os.MkdirTemp(os.TempDir(), "authd-groups-backup"); err == nil {
		defer os.Remove(tmpDir)

		b := filepath.Join(tmpDir, filepath.Base(backupPath))
		err := fileutils.CopyFile(backupPath, b)
		if err == nil {
			log.Debugf(context.Background(), "Backup of %q saved to %q", backupPath, b)
			oldBackup = b
			defer os.Remove(oldBackup)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warningf(context.Background(), "Failed to create backup of %q: %v",
				backupPath, err)
		}
	}

	if err := os.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Warningf(context.Background(), "Failed to remove group file backup: %v", err)
	}

	log.Debugf(context.Background(), "Backing up %q to %q", inputPath, backupPath)
	backupAction := os.Rename
	if fi, _ := os.Lstat(inputPath); fi != nil && fi.Mode()&fs.ModeSymlink != 0 {
		backupAction = fileutils.CopyFile
	}
	if err := backupAction(inputPath, backupPath); err != nil {
		log.Warningf(context.Background(), "Failed make a backup for the group file: %v", err)

		if oldBackup != "" {
			// Backup of current group file failed, let's restore the old backup.
			if err := fileutils.Lrename(oldBackup, backupPath); err != nil {
				log.Warningf(context.Background(), "Failed restoring %q to %q: %v",
					oldBackup, backupPath, err)
			}
		}
	}

	tempPath := groupFileTemporaryPath(groupPath)
	//nolint:gosec // G306 /etc/group should indeed have 0644 permissions
	if err := os.WriteFile(tempPath, []byte(groupsEntries), 0644); err != nil {
		return fmt.Errorf("error writing %s: %w", tempPath, err)
	}

	if err := fileutils.Lrename(tempPath, groupPath); err != nil {
		return fmt.Errorf("error renaming %s to %s: %w", tempPath, groupPath, err)
	}

	l.currentGroups = types.DeepCopyGroupEntries(groups)
	return nil
}

// userLocalGroups returns all groups the user is part of.
func (l *lockedGroups) userLocalGroups(user string) (userGroups []types.GroupEntry) {
	return slices.DeleteFunc(slices.Clone(l.currentGroups), func(g types.GroupEntry) bool {
		return !slices.Contains(g.Users, user)
	})
}
