package users

import (
	"context"
	"errors"
	"slices"
	"sort"
	"sync"

	"github.com/ubuntu/authd/internal/users/localentries"
	userslocking "github.com/ubuntu/authd/internal/users/locking"
)

// IDGenerator is an ID generator that generates UIDs and GIDs in a specific range.
type IDGenerator struct {
	UIDMin uint32
	UIDMax uint32
	GIDMin uint32
	GIDMax uint32

	// IDs generated but not saved to the database yet.
	// This is used to avoid generating the same ID multiple times.
	// We don't differentiate between UIDs and GIDs here, because:
	// * When picking a UID, we avoid IDs which are already used as GIDs,
	//   because the UID is also used as the GID of the user private group.
	// * When picking a GID, we avoid IDs which are already used as UIDs,
	//   because those are also GIDs of the user private groups.
	pendingIDs   []uint32
	pendingIDsMu sync.Mutex

	userManager        *Manager
	getUsedUIDsMock    func() ([]uint32, error)
	getUsedGIDsMock    func() ([]uint32, error)
	isGIDAvailableMock func(gid uint32) (bool, error)
	isUIDAvailableMock func(uid uint32) (bool, error)
}

// GenerateUID generates a random UID in the configured range.
func (g *IDGenerator) GenerateUID(ctx context.Context) (uint32, error) {
	g.pendingIDsMu.Lock()
	defer g.pendingIDsMu.Unlock()

	err := userslocking.CheckUserDBLocked(ctx)
	if err != nil {
		return 0, err
	}

	usedIDs, err := g.getUsedIDs()
	if err != nil {
		return 0, err
	}

	// Add pending UIDs to the used IDs to ensure we don't generate the same UID again
	usedIDs = append(usedIDs, g.pendingIDs...)

	usedIDs = normalizeUsedIDs(usedIDs, g.UIDMin, g.UIDMax)

	for {
		uid, err := getIDCandidate(g.UIDMin, g.UIDMax, usedIDs)
		if err != nil {
			return 0, err
		}

		available, err := g.isUIDAvailable(uid) // Reusing the isGIDAvailable function for UID check
		if err != nil {
			return 0, err
		}

		if available {
			g.pendingIDs = append(g.pendingIDs, uid)
			return uid, nil
		}

		// If the UID is not available, try the next candidate
		usedIDs = append(usedIDs, uid)
	}
}

// GenerateGID generates a random GID in the configured range.
func (g *IDGenerator) GenerateGID(ctx context.Context) (uint32, error) {
	g.pendingIDsMu.Lock()
	defer g.pendingIDsMu.Unlock()

	err := userslocking.CheckUserDBLocked(ctx)
	if err != nil {
		return 0, err
	}

	usedGIDs, err := g.getUsedGIDs()
	if err != nil {
		return 0, err
	}

	// Add pending GIDs to the used GIDs to ensure we don't generate the same GID again
	usedGIDs = append(usedGIDs, g.pendingIDs...)

	usedGIDs = normalizeUsedIDs(usedGIDs, g.GIDMin, g.GIDMax)

	for {
		gid, err := getIDCandidate(g.GIDMin, g.GIDMax, usedGIDs)
		if err != nil {
			return 0, err
		}

		available, err := g.isGIDAvailable(gid)
		if err != nil {
			return 0, err
		}

		if available {
			g.pendingIDs = append(g.pendingIDs, gid)
			return gid, nil
		}

		// If the GID is not available, try the next candidate
		usedGIDs = append(usedGIDs, gid)
	}
}

// ClearPendingIDs clears the pending UIDs and GIDs.
// This function should be called once the generated IDs have been saved to the database.
func (g *IDGenerator) ClearPendingIDs() {
	g.pendingIDsMu.Lock()
	defer g.pendingIDsMu.Unlock()

	g.pendingIDs = nil
}

func getIDCandidate(minID, maxID uint32, usedIDs []uint32) (uint32, error) {
	if minID > maxID {
		return 0, errors.New("minID must be less than or equal to maxID")
	}

	// Find the highest used ID, if any
	var highestUsed uint32
	if len(usedIDs) > 0 {
		highestUsed = usedIDs[len(usedIDs)-1]
	} else if minID > 0 {
		// If there are no used IDs, start from minID
		highestUsed = minID - 1
	} else {
		// If there are no used IDs and minID is 0, start from 0
		highestUsed = 0
	}

	// Try IDs above the highest used
	for id := highestUsed + 1; id <= maxID; id++ {
		_, found := slices.BinarySearch(usedIDs, id)
		if !found {
			return id, nil
		}
	}

	// Fallback: try IDs from minID up to highestUsed
	for id := minID; id <= highestUsed && id <= maxID; id++ {
		_, found := slices.BinarySearch(usedIDs, id)
		if !found {
			return id, nil
		}
	}

	return 0, errors.New("no available ID in range")
}

func (g *IDGenerator) isUIDAvailable(uid uint32) (bool, error) {
	if g.isUIDAvailableMock != nil {
		// If a mock function is provided, use it to check if the UID is available
		return g.isUIDAvailableMock(uid)
	}

	_, err := localentries.GetPasswdByID(uid)
	if !errors.Is(err, localentries.ErrUserNotFound) {
		// We either found the user or there was an error other than "not found"
		return false, err
	}

	// Also check if there is a group with the same ID, because the UID is
	// also used as the GID of the user private group.
	_, err = localentries.GetGroupByID(uid)
	if errors.Is(err, localentries.ErrGroupNotFound) {
		return true, nil
	}

	return false, err
}

func (g *IDGenerator) isGIDAvailable(gid uint32) (bool, error) {
	if g.isGIDAvailableMock != nil {
		// If a mock function is provided, use it to check if the GID is available
		return g.isGIDAvailableMock(gid)
	}

	_, err := localentries.GetGroupByID(gid)
	if errors.Is(err, localentries.ErrGroupNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}

	return false, nil
}

func (g *IDGenerator) getUsedIDs() ([]uint32, error) {
	usedUids, err := g.getUsedUIDs()
	if err != nil {
		return nil, err
	}

	usedGids, err := g.getUsedGIDs()
	if err != nil {
		return nil, err
	}

	return append(usedUids, usedGids...), nil
}

func (g *IDGenerator) getUsedUIDs() ([]uint32, error) {
	if g.getUsedUIDsMock != nil {
		// If a mock function is provided, use it to get the used UIDs
		return g.getUsedUIDsMock()
	}

	// Get the users from the authd database and pre-auth users.
	uids, err := g.userManager.UsedUIDs()
	if err != nil {
		return nil, err
	}

	// Get the user entries from the passwd file. We don't use NSS here, because for picking the next higher ID we only
	// want to consider the users in /etc/passwd and in the authd database, not from other sources like LDAP.
	userEntries, err := localentries.ParseLocalPasswdFile()
	if err != nil {
		return nil, err
	}
	for _, user := range userEntries {
		uids = append(uids, user.UID)
	}

	return uids, nil
}

func (g *IDGenerator) getUsedGIDs() ([]uint32, error) {
	if g.getUsedGIDsMock != nil {
		// If a mock function is provided, use it to get the used GIDs
		return g.getUsedGIDsMock()
	}

	gids, err := g.userManager.UsedGIDs()
	if err != nil {
		return nil, err
	}

	groupManager := localentries.NewGroupManager()
	groupEntries, err := groupManager.GetEntries()
	if err != nil {
		return nil, err
	}
	for _, group := range groupEntries {
		gids = append(gids, group.GID)
	}

	return gids, nil
}

func normalizeUsedIDs(usedIDs []uint32, minID, maxID uint32) []uint32 {
	// Sort usedIDs so we can binary search
	sort.Slice(usedIDs, func(i, j int) bool { return usedIDs[i] < usedIDs[j] })

	// Cut off usedIDs to the range we care about
	if len(usedIDs) > 0 && usedIDs[0] < minID {
		// Find the first ID >= minID
		firstIndex := slices.IndexFunc(usedIDs, func(id uint32) bool { return id >= minID })
		if firstIndex != -1 {
			// Slice usedIDs to start from the first ID >= minID
			usedIDs = usedIDs[firstIndex:]
		}
	}
	if len(usedIDs) > 0 && usedIDs[len(usedIDs)-1] > maxID {
		// Find the last ID <= maxID
		lastIndex := slices.IndexFunc(usedIDs, func(id uint32) bool { return id > maxID })
		if lastIndex != -1 {
			// Slice usedIDs to end at the last ID <= maxID
			usedIDs = usedIDs[:lastIndex]
		}
	}

	// Remove duplicates from usedIDs
	return slices.Compact(usedIDs)
}
