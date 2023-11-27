package main

import (
	"github.com/msteinert/pam"
)

// Various signalling return messaging to PAM.

// pamReturnStatus is the interface that all PAM return types should implement.
type pamReturnStatus interface {
	Message() string
}

// pamReturnError is an interface that PAM errors return types should implement.
type pamReturnError interface {
	pamReturnStatus
	Status() pam.StatusError
}

// pamSuccess signals PAM module to return with provided pam.Success and Quit tea.Model.
type pamSuccess struct {
	brokerID string
	msg      string
}

// Message returns the message that should be sent to pam as info message.
func (p pamSuccess) Message() string {
	return p.msg
}

// pamIgnore signals PAM module to return pam.Ignore and Quit tea.Model.
type pamIgnore struct {
	msg           string
	localBrokerID string // Only set for local broker to store it globally.
}

// Status returns [pam.ErrIgnore]
func (p pamIgnore) Status() pam.StatusError {
	return pam.ErrIgnore
}

// Message returns the message that should be sent to pam as info message.
func (p pamIgnore) Message() string {
	return p.msg
}

// pamIgnore signals PAM module to return the provided error message and Quit tea.Model.
type pamError struct {
	msg    string
	status pam.StatusError
}

// Status returns the PAM exit status code.
func (p pamError) Status() pam.StatusError {
	return p.status
}

// Message returns the message that should be sent to pam as error message.
func (p pamError) Message() string {
	if p.msg != "" {
		return p.msg
	}
	return p.status.Error()
}
