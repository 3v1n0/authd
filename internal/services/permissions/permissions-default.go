//go:build !integrationtests && !withexamplebroker

package permissions

// DefaultCurrentUserAsRoot mocks the current user as root for the permission manager.
func DefaultCurrentUserAsRoot() {
	panic("This cannot be called from production code")
}
