package testutils

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd"
)

// GdmRequireEqualData ensures that data is equal by checking the marshalled values.
func GdmRequireEqualData(t *testing.T, want any, actual any) {
	t.Helper()

	wantJSON, err := json.MarshalIndent(want, "", "  ")
	require.NoError(t, err)
	actualJSON, err := json.MarshalIndent(actual, "", "  ")
	require.NoError(t, err)

	require.Equal(t, string(wantJSON), string(actualJSON))
}

// GdmDataToJSON is a test helper function to convert GDM data to JSON.
func GdmDataToJSON(t *testing.T, data *gdm.Data) string {
	t.Helper()

	json, err := data.JSON()
	require.NoError(t, err)
	return string(json)
}

// GdmSelectUserEvent generates a SelectUser event.
func GdmSelectUserEvent(username string) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_userSelected,
		Data: &gdm.EventData_UserSelected{
			UserSelected: &gdm.Events_UserSelected{UserId: username},
		},
	}
}

// GdmSelectBrokerEvent generates a SelectBroker event.
func GdmSelectBrokerEvent(brokerID string) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_brokerSelected,
		Data: &gdm.EventData_BrokerSelected{
			BrokerSelected: &gdm.Events_BrokerSelected{BrokerId: brokerID},
		},
	}
}

// GdmChangeStageEvent generates a ChangeStage event.
func GdmChangeStageEvent(stage proto.Stage) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_stageChanged,
		Data: &gdm.EventData_StageChanged{
			StageChanged: &gdm.Events_StageChanged{Stage: stage},
		},
	}
}

// GdmAuthModeSelectedEvent generates a AuthModeSelected event.
func GdmAuthModeSelectedEvent(authModeID string) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_authModeSelected,
		Data: &gdm.EventData_AuthModeSelected{
			AuthModeSelected: &gdm.Events_AuthModeSelected{
				AuthModeId: authModeID,
			},
		},
	}
}

// GdmIsAuthenticatedEvent generates a IsAuthenticated event.
func GdmIsAuthenticatedEvent(item authd.IARequestAuthenticationDataItem) *gdm.EventData {
	return &gdm.EventData{
		Type: gdm.EventType_isAuthenticatedRequested,
		Data: &gdm.EventData_IsAuthenticatedRequested{
			IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
				AuthenticationData: &authd.IARequest_AuthenticationData{Item: item},
			},
		},
	}
}
