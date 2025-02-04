// Package userstestutils export db test functionalities used by other packages.
package userstestutils

import (
	"unsafe"

	"github.com/ubuntu/authd/internal/testsdetection"
	"github.com/ubuntu/authd/internal/users"
	"github.com/ubuntu/authd/internal/users/db"
)

func init() {
	// No import outside of testing environment.
	testsdetection.MustBeTesting()
}

type manager struct {
	db *db.Database
}

// GetManagerDB returns the database of the manager.
func GetManagerDB(m *users.Manager) *db.Database {
	//#nosec:G103 // This is only used in tests.
	mTest := *(*manager)(unsafe.Pointer(m))

	return mTest.db
}
