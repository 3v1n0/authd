package users

import (
	"errors"

	"github.com/ubuntu/authd/internal/users/db"
	"github.com/ubuntu/authd/internal/users/tempentries"
)

func (m *Manager) PreAuthUserRecords() *tempentries.PreAuthUserRecords {
	return m.preAuthRecords
}

func (m *Manager) DB() *db.Manager {
	return m.db
}

func (m *Manager) MockIDGenerator() error {
	idGenerator, ok := m.idGenerator.(*IDGenerator)
	if !ok {
		return errors.New("IDGenerator is not of type *IDGenerator")
	}

	idGenerator.getUsedUIDsMock = m.UsedUIDs
	idGenerator.getUsedGIDsMock = m.UsedGIDs
	idGenerator.isUIDAvailableMock = m.isUIDAvailableMock
	idGenerator.isGIDAvailableMock = m.isGIDAvailableMock

	return nil
}

func (m *Manager) isUIDAvailableMock(uid uint32) (bool, error) {
	_, err := m.UserByID(uid)
	if errors.Is(err, db.NoDataFoundError{}) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func (m *Manager) isGIDAvailableMock(gid uint32) (bool, error) {
	_, err := m.GroupByID(gid)
	if errors.Is(err, db.NoDataFoundError{}) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}
