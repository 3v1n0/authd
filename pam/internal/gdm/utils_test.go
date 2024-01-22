package gdm

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func reformatJSONIndented(t *testing.T, input []byte) []byte {
	t.Helper()

	var indented bytes.Buffer
	err := json.Indent(&indented, input, "", "  ")
	require.NoError(t, err)
	return indented.Bytes()
}

func RequireEqualData(t *testing.T, want *Data, actual *Data) {
	t.Helper()

	wantJSON, err := want.JSON()
	require.NoError(t, err)
	actualJSON, err := actual.JSON()
	require.NoError(t, err)

	require.Equal(t, string(reformatJSONIndented(t, wantJSON)),
		string(reformatJSONIndented(t, actualJSON)))
}
