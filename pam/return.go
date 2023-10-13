package main

import (
	"github.com/msteinert/pam"
)

// Various signalling return messaging to PAM.

type pamReturnStatus interface {
	Status() pam.Status
	Error() string
}

// newPamStatus returns a new pamStatus.
func newPamStatus(status pam.Status, err error) pamReturnStatus {
	return pam.NewTransactionError(err, status)
}

// pamStatus signals PAM module to return with provided pam.Success and Quit tea.Model.
type pamSuccess struct {
	pam.TransactionError
	brokerID string
}

// newPamSuccess returns a new pamSuccess.
func newPamSuccess(brokerID string) pamSuccess {
	return pamSuccess{
		pam.NewTransactionError(nil, pam.Success),
		brokerID,
	}
}

// pamIgnore signals PAM module to return pam.Ignore and Quit tea.Model.
type pamIgnore struct {
	pam.TransactionError
	localBrokerID string // Only set for local broker to store it globally.
}

// newPamIgnore returns a new pamIgnore.
func newPamIgnore(localBrokerID string, err error) pamIgnore {
	return pamIgnore{
		pam.NewTransactionError(err, pam.Success),
		localBrokerID,
	}
}
