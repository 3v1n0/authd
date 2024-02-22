//FIXME: This should not be necessary, but generating a generate-only
// folder breaks the generation during build phase as per:
// https://salsa.debian.org/go-team/packages/dh-golang/-/merge_requests/22

//go:build generate

//go:generate go generate -C testdata/grpctestservice

package daemon
