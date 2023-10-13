package main

import (
	"github.com/msteinert/pam"
)

// Various signalling return messaging to PAM.

type pamReturnStatus interface {
	Status() pam.StatusError
	Error() string
}

// TODO: Remove this when we've tests coverage that ensures this is the case.
// ensure that [pam.NewTransactionError] implements [pamReturnStatus].
var _ pamReturnStatus = pam.NewTransactionError(pam.ErrAbort, nil)

// pamStatus signals PAM module to return with provided pam.Success and Quit tea.Model.
type pamSuccess struct {
	pam.TransactionError
	brokerID string
}

// newPamSuccess returns a new pamSuccess.
func newPamSuccess(brokerID string) pamSuccess {
	return pamSuccess{TransactionError: nil, brokerID: brokerID}
}

// pamIgnore signals PAM module to return pam.Ignore and Quit tea.Model.
type pamIgnore struct {
	pam.TransactionError
	localBrokerID string // Only set for local broker to store it globally.
}

// newPamIgnore returns a new pamIgnore.
func newPamIgnore(localBrokerID string, err error) pamIgnore {
	return pamIgnore{
		TransactionError: pam.NewTransactionError(pam.ErrIgnore, err),
		localBrokerID:    localBrokerID,
	}
}
