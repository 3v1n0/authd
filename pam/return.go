package main

import (
	"github.com/msteinert/pam"
)

// Various signalling return messaging to PAM.

type pamReturnStatus interface {
	Status() pam.StatusError
	Error() string
}

// ensure that [pam.NewTransactionError] implements [pamReturnStatus].
var _ pamReturnStatus = pam.NewTransactionError(pam.ErrAbort, nil)

// pamStatus signals PAM module to return with provided pam.Success and Quit tea.Model.
type pamSuccess struct {
	pam.TransactionError
	brokerID string
}

// newPamSuccess returns a new pamSuccess.
func newPamSuccess(brokerID string) pamReturnStatus {
	return pamSuccess{nil, brokerID}
}

// pamIgnore signals PAM module to return pam.Ignore and Quit tea.Model.
type pamIgnore struct {
	pam.TransactionError
	localBrokerID string // Only set for local broker to store it globally.
}

// newPamIgnore returns a new pamIgnore.
func newPamIgnore(localBrokerID string, err error) pamReturnStatus {
	return pamIgnore{
		pam.NewTransactionError(pam.ErrIgnore, err),
		localBrokerID,
	}
}
