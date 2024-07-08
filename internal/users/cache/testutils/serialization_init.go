//go:build !withexamplebroker && !integrationtests

package cachetestutils

import "github.com/ubuntu/authd/internal/testsdetection"

func init() {
	// No import outside of testing environment.
	testsdetection.MustBeTesting()
}
