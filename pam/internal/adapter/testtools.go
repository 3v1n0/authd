// Add build tag!!

package adapter

import "github.com/ubuntu/authd"

type TestSupportedUILayoutsReceived = supportedUILayoutsReceived

func (t *TestSupportedUILayoutsReceived) Layouts() []*authd.UILayout { return t.layouts }

// type AuthModesReceived = authModesReceived

// func (t *AuthModesReceived) AuthModes() []*authd.GAMResponse_AuthenticationMode { return t.authModes }

type TestAuthModeSelected = authModeSelected

func (t *TestAuthModeSelected) AuthModeID() string { return t.id }

type TestUserSelected = userSelected

func (t *TestUserSelected) UserName() string { return t.username }

type TestBrokerSelected = brokerSelected

func (t *TestBrokerSelected) BrokerID() string { return t.brokerID }

type TestSessionStarted = SessionStarted

func (t *TestSessionStarted) BrokerID() string      { return t.brokerID }
func (t *TestSessionStarted) SessionID() string     { return t.sessionID }
func (t *TestSessionStarted) EncryptionKey() string { return t.encryptionKey }
