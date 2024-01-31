package adapter

import (
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/pam/internal/gdm"
	"github.com/ubuntu/authd/pam/internal/proto"
	"golang.org/x/exp/constraints"
)

func isSupersetOf[T constraints.Integer](a []T, b []T) bool {
	tracker := make(map[T]int)
	for _, v := range a {
		tracker[v]++
	}

	for _, value := range b {
		n, found := tracker[value]
		if !found {
			return false
		}
		if n < 1 {
			return false
		}
		tracker[value] = n - 1
	}
	return true
}

func gdmTestSelectUserEvent(username string) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_userSelected,
		Data: &gdm.EventData_UserSelected{
			UserSelected: &gdm.Events_UserSelected{UserId: username},
		},
	}
}

func gdmTestSelectBrokerEvent(brokerID string) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_brokerSelected,
		Data: &gdm.EventData_BrokerSelected{
			BrokerSelected: &gdm.Events_BrokerSelected{BrokerId: brokerID},
		},
	}
}

func gdmTestChangeStageEvent(stage proto.Stage) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_stageChanged,
		Data: &gdm.EventData_StageChanged{
			StageChanged: &gdm.Events_StageChanged{Stage: stage},
		},
	}
}

func gdmTestAuthModeSelectedEvent(authModeID string) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_authModeSelected,
		Data: &gdm.EventData_AuthModeSelected{
			AuthModeSelected: &gdm.Events_AuthModeSelected{
				AuthModeId: authModeID,
			},
		},
	}
}

func gdmTestIsAuthenticatedEvent(item authd.IARequestAuthenticationDataItem) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_isAuthenticatedRequested,
		Data: &gdm.EventData_IsAuthenticatedRequested{
			IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
				AuthenticationData: &authd.IARequest_AuthenticationData{Item: item},
			},
		},
	}
}
