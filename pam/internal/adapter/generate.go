//go:build generate

// Package adapter contains the PAM remote UI adapters.
package adapter

//go:generate ../../../tools/generate-proto.sh pam.proto
