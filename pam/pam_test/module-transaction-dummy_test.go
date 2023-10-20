package pam_test

import (
	"testing"

	"github.com/msteinert/pam"
	"github.com/stretchr/testify/require"
)

type binConvFunc func(pam.BinaryPointer) ([]byte, error)

func (f binConvFunc) RespondPAMBinary(ptr pam.BinaryPointer) ([]byte, error) {
	return f(ptr)
}

func (f binConvFunc) RespondPAM(pam.Style, string) (string, error) {
	return "", pam.ConvErr
}

func TestModuleTransactionDummy(t *testing.T) {
	t.Parallel()
	t.Cleanup(MaybeDoLeakCheck)

	testCases := map[string]struct {
		testFunc    func(*testing.T, pam.ModuleTransaction)
		convHandler pam.ConversationHandler
	}{
		"SetItem": {
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				err := tx.SetItem(pam.User, "an user")
				require.NoError(t, err, "SetItem should not return an error")
			},
		},

		"GetItem Empty": {
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				val, err := tx.GetItem(pam.User)
				require.NoError(t, err, "GetItem should not return an error")
				require.Equal(t, "", val)
			},
		},

		"GetSetItem": {
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				err := tx.SetItem(pam.User, "an user")
				require.NoError(t, err, "SetItem should not return an error")
				val, err := tx.GetItem(pam.User)
				require.NoError(t, err, "GetItem should not return an error")
				require.Equal(t, "an user", val)
			},
		},

		"GetEnv Empty": {
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				val := tx.GetEnv("AN_ENV")
				require.Equal(t, "", val)
			},
		},

		"PutEnvGetEnv": {
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				list, err := tx.GetEnvList()
				require.NoError(t, err, "GetEnvList should not return an error")
				require.Equal(t, map[string]string{}, list)

				err = tx.PutEnv("AN_ENV")
				require.NoError(t, err, "PutEnv should not return an error")

				val := tx.GetEnv("AN_ENV")
				require.Equal(t, "", val)

				list, err = tx.GetEnvList()
				require.NoError(t, err, "GetEnvList should not return an error")
				require.Equal(t, map[string]string{}, list)

				err = tx.PutEnv("OTHER_ENV=value")
				require.NoError(t, err, "PutEnv should not return an error")
				val = tx.GetEnv("OTHER_ENV")
				require.Equal(t, "value", val)

				list, err = tx.GetEnvList()
				require.NoError(t, err, "GetEnvList should not return an error")
				require.Equal(t, map[string]string{"OTHER_ENV": "value"}, list)

				err = tx.PutEnv("OTHER_ENV=")
				require.NoError(t, err, "PutEnv should not return an error")
				val = tx.GetEnv("OTHER_ENV")
				require.Equal(t, "", val)

				list, err = tx.GetEnvList()
				require.NoError(t, err, "GetEnvList should not return an error")
				require.Equal(t, map[string]string{"OTHER_ENV": ""}, list)

				err = tx.PutEnv("OTHER_ENV")
				require.NoError(t, err, "PutEnv should not return an error")
				val = tx.GetEnv("OTHER_ENV")
				require.Equal(t, "", val)

				list, err = tx.GetEnvList()
				require.NoError(t, err, "GetEnvList should not return an error")
				require.Equal(t, map[string]string{}, list)
			},
		},

		"PutEnv Invalid": {
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				err := tx.PutEnv("=INVALID")
				require.ErrorIs(t, err, pam.BadItem)
			},
		},

		"GetData Missing": {
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				data, err := tx.GetData("not set")
				require.ErrorIs(t, err, pam.NoModuleData)
				require.Equal(t, nil, data)
			},
		},

		"SetGetData": {
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				err := tx.SetData("some-data", ModuleTransactionDummy{
					Items: map[pam.Item]string{pam.Tty: "yay"},
					Env:   map[string]string{"foo": "bar"},
				})
				require.NoError(t, err)

				data, err := tx.GetData("some-data")
				require.NoError(t, err)
				require.Equal(t, ModuleTransactionDummy{
					Items: map[pam.Item]string{pam.Tty: "yay"},
					Env:   map[string]string{"foo": "bar"},
				}, data)
			},
		},

		"GetUserPreset": {
			convHandler: pam.ConversationFunc(
				func(s pam.Style, msg string) (string, error) {
					return "something-else", pam.ConvErr
				}),
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				err := tx.SetItem(pam.User, "pam-user")
				require.NoError(t, err)

				user, err := tx.GetUser("who are you?")
				require.NoError(t, err)
				require.Equal(t, "pam-user", user)
			},
		},

		"GetUserUnsetMissingConv": {
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()

				user, err := tx.GetUser("who are you?")
				require.ErrorIs(t, err, pam.ConvErr)
				require.Equal(t, "", user)
			},
		},

		"GetUserUnsetViaConv": {
			convHandler: pam.ConversationFunc(
				func(s pam.Style, msg string) (string, error) {
					switch s {
					case pam.PromptEchoOn:
						return "provided-user", nil
					}
					return "", pam.ConvErr
				}),
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				user, err := tx.GetUser("who are you?")
				require.NoError(t, err)
				require.Equal(t, "provided-user", user)
			},
		},

		"StartStringConvf": {
			convHandler: pam.ConversationFunc(
				func(s pam.Style, msg string) (string, error) {
					switch s {
					case pam.TextInfo:
						require.Equal(t, "Sending some info, right? true", msg)
						return "And returning some text back", nil
					}
					return "", pam.ConvErr
				}),
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				user, err := tx.StartStringConvf(pam.TextInfo, "Sending some %s, right? %v",
					"info", true)
				require.NoError(t, err)
				require.NotNil(t, user)
				require.Equal(t, pam.TextInfo, user.Style())
				require.Equal(t, "And returning some text back", user.Response())
			},
		},

		"StartStringConvFailing": {
			convHandler: pam.ConversationFunc(
				func(s pam.Style, msg string) (string, error) {
					return "", pam.BufErr
				}),
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				user, err := tx.StartStringConv(pam.TextInfo, "")
				require.ErrorIs(t, err, pam.BufErr)
				require.Zero(t, user)
			},
		},

		"StartBinaryConf": {
			convHandler: binConvFunc(
				func(ptr pam.BinaryPointer) ([]byte, error) {
					require.NotNil(t, ptr)
					bytes := getBinaryFromPointer(ptr, 3)
					require.Equal(t, []byte{0x01, 0x02, 0x03}, bytes)
					return append(bytes, 0x04), nil
				}),
			testFunc: func(t *testing.T, tx pam.ModuleTransaction) {
				t.Helper()
				data, err := tx.StartBinaryConv([]byte{0x01, 0x02, 0x03})
				require.NoError(t, err)
				require.NotNil(t, data)
				require.Equal(t, pam.BinaryPrompt, data.Style())
				require.NotNil(t, data.Data())
				bytes := *(*[]byte)(data.Data())
				require.Equal(t, []byte{0x01, 0x02, 0x03, 0x4}, bytes)
			},
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(MaybeDoLeakCheck)
			tc.testFunc(t, NewModuleTransactionDummy(tc.convHandler))
		})
	}
}
