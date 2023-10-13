package main

import (
	"testing"

	"github.com/msteinert/pam"
	"github.com/stretchr/testify/require"
)

func Test_ModuleTransactionDummy_SetItem(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(nil)
	err := tx.SetItem(pam.User, "an user")
	require.NoError(t, err, "SetItem should not return an error")
}

func Test_ModuleTransactionDummy_GetItem_Empty(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(nil)
	val, err := tx.GetItem(pam.User)
	require.NoError(t, err, "GetItem should not return an error")
	require.Equal(t, "", val)
}

func Test_ModuleTransactionDummy_GetSetItem(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(nil)
	err := tx.SetItem(pam.User, "an user")
	require.NoError(t, err, "SetItem should not return an error")
	val, err := tx.GetItem(pam.User)
	require.NoError(t, err, "GetItem should not return an error")
	require.Equal(t, "an user", val)
}

func Test_ModuleTransactionDummy_GetEnv_Empty(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(nil)
	val := tx.GetEnv("AN_ENV")
	require.Equal(t, "", val)
}

func Test_ModuleTransactionDummy_PutEnvGetEnv(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(nil)
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
}

func Test_ModuleTransactionDummy_PutEnv_Invalid(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(nil)
	err := tx.PutEnv("=INVALID")
	require.ErrorIs(t, err, pam.BadItem)
}

func Test_ModuleTransactionDummy_GetData_Missing(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(nil)
	data, err := tx.GetData("not set")
	require.ErrorIs(t, err, pam.NoModuleData)
	require.Equal(t, nil, data)
}

func Test_ModuleTransactionDummy_SetGetData(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(nil)
	err := tx.SetData("some-data", PamModuleTransactionDummy{
		Items: map[pam.Item]string{pam.Tty: "yay"},
		Env:   map[string]string{"foo": "bar"},
	})
	require.NoError(t, err)

	data, err := tx.GetData("some-data")
	require.NoError(t, err)
	require.Equal(t, PamModuleTransactionDummy{
		Items: map[pam.Item]string{pam.Tty: "yay"},
		Env:   map[string]string{"foo": "bar"},
	}, data)
}

func Test_ModuleTransactionDummy_GetUser_Preset(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(pam.ConversationFunc(
		func(s pam.Style, msg string) (string, error) {
			return "something-else", pam.ConvErr
		}))
	err := tx.SetItem(pam.User, "pam-user")
	require.NoError(t, err)

	user, err := tx.GetUser("who are you?")
	require.NoError(t, err)
	require.Equal(t, "pam-user", user)
}

func Test_ModuleTransactionDummy_GetUser_Unset_MissingConv(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(nil)

	user, err := tx.GetUser("who are you?")
	require.ErrorIs(t, err, pam.ConvErr)
	require.Equal(t, "", user)
}

func Test_ModuleTransactionDummy_GetUser_Unset_ViaConv(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(pam.ConversationFunc(
		func(s pam.Style, msg string) (string, error) {
			switch s {
			case pam.PromptEchoOn:
				return "provided-user", nil
			}
			return "", pam.ConvErr
		}))

	user, err := tx.GetUser("who are you?")
	require.NoError(t, err)
	require.Equal(t, "provided-user", user)
}

func Test_ModuleTransactionDummy_StartStringConvf(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(pam.ConversationFunc(
		func(s pam.Style, msg string) (string, error) {
			switch s {
			case pam.TextInfo:
				require.Equal(t, "Sending some info, right? true", msg)
				return "And returning some text back", nil
			}
			return "", pam.ConvErr
		}))

	user, err := tx.StartStringConvf(pam.TextInfo, "Sending some %s, right? %v",
		"info", true)
	require.NoError(t, err)
	require.NotNil(t, user)
	require.Equal(t, pam.TextInfo, user.Style())
	require.Equal(t, "And returning some text back", user.Response())
}

func Test_ModuleTransactionDummy_StartStringConvFailing(t *testing.T) {
	t.Parallel()
	tx := NewPamModuleTransactionDummy(pam.ConversationFunc(
		func(s pam.Style, msg string) (string, error) {
			return "", pam.BufErr
		}))

	user, err := tx.StartStringConv(pam.TextInfo, "")
	require.ErrorIs(t, err, pam.BufErr)
	require.Zero(t, user)
}

type binConvFunc func(pam.BinaryPointer) ([]byte, error)

func (f binConvFunc) RespondPAMBinary(ptr pam.BinaryPointer) ([]byte, error) {
	return f(ptr)
}

func (f binConvFunc) RespondPAM(pam.Style, string) (string, error) {
	return "", pam.ConvErr
}

func Test_ModuleTransactionDummy_StartBinaryConf(t *testing.T) {
	t.Parallel()

	tx := NewPamModuleTransactionDummy(binConvFunc(
		func(ptr pam.BinaryPointer) ([]byte, error) {
			require.NotNil(t, ptr)
			bytes := getBinaryFromPointer(ptr, 3)
			require.Equal(t, []byte{0x01, 0x02, 0x03}, bytes)
			return append(bytes, 0x04), nil
		}))

	data, err := tx.StartBinaryConv([]byte{0x01, 0x02, 0x03})
	require.NoError(t, err)
	require.NotNil(t, data)
	require.Equal(t, pam.BinaryPrompt, data.Style())
	require.NotNil(t, data.Data())
	bytes := *(*[]byte)(data.Data())
	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x4}, bytes)
}
