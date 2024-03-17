package main_test

import (
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/internal/testutils"
	"github.com/ubuntu/authd/pam/internal/pam_test"
)

func cliMethodCallFormat(method string, args []any, ret []any, formats ...any) string {
	mc := method

	argsParser := func(values []any) string {
		var strValues []string
		for _, r := range values {
			switch v := r.(type) {
			case pam.Error:
				r = int(v)
			// case string:
			case int:
			default:
				r = getVariantString(r)
			}
			// if pamError, ok := r.(pam.Error); ok {
			// 	r = int(pamError)
			// }
			strValues = append(strValues, fmt.Sprint(r))
		}
		return strings.Join(strValues, ";")
	}

	mc += "|" + argsParser(args)

	if ret != nil {
		mc += "|" + argsParser(ret)
	}

	return fmt.Sprintf(mc, formats...)
}

type cliMethodCall struct {
	// m is the method name to call.
	m string
	// args is the arguments to pass to the method.
	args []any
	// r is the expected method return values
	r []any
}

func (cmc cliMethodCall) format() string {
	return cliMethodCallFormat(cmc.m, cmc.args, cmc.r)
}

func methodCallsAsArgs(methodCalls []cliMethodCall) []string {
	var args []string
	for _, mc := range methodCalls {
		args = append(args, mc.format())
	}
	return args
}

func TestExecModule(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	if !pam.CheckPamHasStartConfdir() {
		t.Fatal("can't test with this libpam version!")
	}

	pkgConfigDeps := []string{"gio-2.0", "gio-unix-2.0"}
	sources := []string{"../go-exec/module.c"}
	libPath := buildCPAMModule(t, sources, pkgConfigDeps, "pam_authd_exec")

	execClient := buildExecClient(t)

	baseModuleArgs := []string{
		execClient,
		"--debug",
	}
	if env := testutils.CoverDirEnv(); env != "" {
		baseModuleArgs = append(baseModuleArgs, "-e", testutils.CoverDirEnv())
	}

	moduleInitTests := map[string]struct {
		moduleArgs []string
		wantError  error
	}{
		// Error cases
		"Error on no arguments": {
			wantError: pam.ErrModuleUnknown,
		},

		"Error on empty executable parameter": {
			moduleArgs: []string{""},
			wantError:  pam.ErrModuleUnknown,
		},

		"Error on non existent executable parameter": {
			moduleArgs: []string{"/non-existent/file"},
			wantError:  pam.ErrModuleUnknown,
		},

		"Error on non executable parameter": {
			moduleArgs: sources,
			wantError:  pam.ErrModuleUnknown,
		},
	}
	for name, tc := range moduleInitTests {
		t.Run("ModuleInit "+name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			tx := preparePamTransaction(t, libPath, tc.moduleArgs, "")
			require.ErrorIs(t, tx.Authenticate(0), tc.wantError)
		})
	}

	// moduleArgs := append(slices.Clone(baseModuleArgs), "PutEnv|Fooo=bar|0")
	// moduleArgs = append(moduleArgs, "GetEnv|Fooo")
	// moduleArgs = append(moduleArgs, "SetItem|-1,fooo bar|29")

	// serviceFile := createServiceFile(t, "exec-module", libPath, moduleArgs,
	// 	pamDebugIgnoreError)

	// cnt, err := os.ReadFile(serviceFile)
	// fmt.Println("Service file content")
	// fmt.Println(string(cnt), err)

	// tx, err := pam.StartConfDir(filepath.Base(serviceFile), "", nil, filepath.Dir(serviceFile))
	// require.NoError(t, err, "PAM: Error to initialize module")
	// require.NotNil(t, tx, "PAM: Transaction is not set")
	// t.Cleanup(func() { require.NoError(t, tx.End(), "PAM: can't end transaction") })

	// require.NoError(t, tx.Authenticate(0))
	// return

	// The tests below are based on the ones of the pam_test.ModuleTransactionDummy
	// but we're using the exec commands to ensure that everything works as expected.
	// We don't split the tests in different functions not to to have to regenerate the
	// same library for each test and to ensure that the C coverage is properly computed.

	// These tests are meant to check the exec client behavior itself.
	cliTests := map[string]struct {
		args        []string
		methodCalls []cliMethodCall
		wantError   error
	}{
		"SetGet Item": {
			methodCalls: []cliMethodCall{
				{m: "SetItem", args: []any{pam.Rhost, "some-rhost-value"}, r: []any{pam.Error(0)}},
				{m: "GetItem", args: []any{pam.Rhost}, r: []any{"some-rhost-value", pam.Error(0)}},
			},
			args: []string{
				// fmt.Sprintf("SetItem|%d;some-rhost-value|0", pam.Rhost),
				// fmt.Sprintf("GetItem|%d|some-rhost-value;0", pam.Rhost),
				cliMethodCallFormat("SetItem", []any{pam.Rhost, "some-rhost-value"}, []any{pam.Error(0)}),
				cliMethodCallFormat("GetItem", []any{pam.Rhost}, []any{"some-rhost-value", pam.Error(0)}),
			},
		},
		"SetGet Item handling errors": {
			args: []string{
				// fmt.Sprintf("SetItem|%d;some-value|%d", pam.Item(-1), pam.ErrBadItem),
				// fmt.Sprintf("GetItem|%d|;%d", pam.Item(-1), pam.ErrBadItem),
				cliMethodCallFormat("SetItem", []any{pam.Item(-1), "some-value"}, []any{pam.ErrBadItem}),
				cliMethodCallFormat("GetItem", []any{pam.Item(-1)}, []any{"", pam.ErrBadItem}),
			},
			methodCalls: []cliMethodCall{
				{m: "SetItem", args: []any{pam.Item(-1), "some-value"}, r: []any{pam.ErrBadItem}},
				{m: "GetItem", args: []any{pam.Item(-1)}, r: []any{"", pam.ErrBadItem}},
			},
		},
		"SetGet Env": {
			methodCalls: []cliMethodCall{
				{m: "PutEnv", args: []any{"FooEnv=bar"}, r: []any{pam.Error(0)}},
				{m: "GetEnv", args: []any{"FooEnv"}, r: []any{"bar"}},
				{m: "GetEnv", args: []any{"AnotherEnv"}, r: []any{}},

				{m: "PutEnv", args: []any{"FooEnv="}},
				{m: "GetEnv", args: []any{"FooEnv"}, r: []any{}},

				{m: "PutEnv", args: []any{"FooEnv"}},
				{m: "GetEnv", args: []any{"FooEnv"}, r: []any{}},
			},
			args: []string{
				cliMethodCallFormat("PutEnv", []any{"FooEnv=bar"}, []any{pam.Error(0)}),
				cliMethodCallFormat("GetEnv", []any{"FooEnv"}, []any{"bar"}),
				cliMethodCallFormat("GetEnv", []any{"AnotherEnv"}, []any{}),

				cliMethodCallFormat("PutEnv", []any{"FooEnv="}, nil),
				cliMethodCallFormat("GetEnv", []any{"FooEnv"}, []any{}),

				cliMethodCallFormat("PutEnv", []any{"FooEnv"}, nil),
				cliMethodCallFormat("GetEnv", []any{"FooEnv"}, []any{}),

				// "PutEnv|FooEnv=bar|0",
				// "GetEnv|FooEnv|bar",
				// "GetEnv|AnotherEnv|",

				// "PutEnv|FooEnv=",
				// "GetEnv|FooEnv|",

				// "PutEnv|FooEnv",
				// "GetEnv|FooEnv|",
			},
		},
		"SetGet Data": {
			methodCalls: []cliMethodCall{
				{m: "SetData", args: []any{"FooData", "bar"}, r: []any{pam.Error(0)}},
				{m: "GetData", args: []any{"FooData"}, r: []any{"bar", pam.Error(0)}},

				{m: "GetData", args: []any{"AnotherData"}, r: []any{nil, pam.ErrNoModuleData}},

				{m: "SetData", args: []any{"FooData", []int{1, 2, 3}}},
				{m: "GetData", args: []any{"FooData"}, r: []any{[]int{1, 2, 3}, pam.Error(0)}},

				{m: "SetData", args: []any{"FooData", nil}},
				{m: "GetData", args: []any{"FooData"}, r: []any{nil, pam.ErrNoModuleData}},
			},
			args: []string{
				cliMethodCallFormat("SetData", []any{"FooData", "bar"}, []any{pam.Error(0)}),
				// "SetData|FooData;bar|0",
				cliMethodCallFormat("GetData", []any{"FooData"}, []any{"bar", pam.Error(0)}),
				// "GetData|FooData|bar;0",

				// fmt.Sprintf("GetData|AnotherData|%s;%d", getVariantString(nil), pam.ErrNoModuleData),
				cliMethodCallFormat("GetData", []any{"AnotherData"}, []any{nil, pam.ErrNoModuleData}),
				// cliMethodCall("GetData", []string{"AnotherData"}, []string{"%s", "%d"},
				// 	getVariantString(nil), pam.ErrNoModuleData),

				cliMethodCallFormat("SetData", []any{"FooData", []int{1, 2, 3}}, nil),
				// fmt.Sprintf("SetData|FooData;%s", getVariantString([]int{1, 2, 3})),
				// fmt.Sprintf("GetData|FooData|%s;0", getVariantString([]int{1, 2, 3})),
				cliMethodCallFormat("GetData", []any{"FooData"}, []any{[]int{1, 2, 3}, pam.Error(0)}),

				// fmt.Sprintf("SetData|FooData;%s", getVariantString(nil)),
				cliMethodCallFormat("SetData", []any{"FooData", nil}, nil),
				// fmt.Sprintf("GetData|FooData|%s;%d", getVariantString(nil),
				// 	pam.ErrNoModuleData),
				cliMethodCallFormat("GetData", []any{"FooData"}, []any{nil, pam.ErrNoModuleData}),
			},
		},
		"GetEnvList empty": {
			methodCalls: []cliMethodCall{
				// FIXME: making adding args automatic...
				{m: "GetEnvList", r: []any{map[string]string{}, pam.Error(0)}},
			},
			args: []string{fmt.Sprintf("GetEnvList||%s;0", getVariantString(map[string]string{}))},
		},
		"GetEnvList populated": {
			methodCalls: []cliMethodCall{
				{m: "PutEnv", args: []any{"Env=value"}},
				{m: "PutEnv", args: []any{"Env2=value2"}},
				{m: "GetEnvList", r: []any{
					map[string]string{
						"Env":  "value",
						"Env2": "value2",
					},
					pam.Error(0),
				}},
			},
			args: []string{
				"PutEnv|Env=value",
				"PutEnv|Env2=value2",
				fmt.Sprintf("GetEnvList||%s;0", getVariantString(map[string]string{
					"Env":  "value",
					"Env2": "value2",
				})),
			},
		},

		// Error cases
		"Error when miss arguments": {
			// methodCalls: []cliMethodCall{{m: "SetItem"}},
			args:      []string{"SetItem"},
			wantError: pam_test.ErrorInvalidArguments,
		},
		"Error when not providing no arguments": {
			args:      []string{"SetData|"},
			wantError: pam_test.ErrorInvalidArguments,
		},
		"Error when providing empty arguments": {
			methodCalls: []cliMethodCall{{m: "SetItem", args: []any{}}},
			args:        []string{fmt.Sprintf("SetItem|%d", pam.User)},
			wantError:   pam_test.ErrorInvalidArguments,
		},
		"Error when not providing enough arguments": {
			methodCalls: []cliMethodCall{{m: "SetItem", args: []any{pam.User}}},
			args:        []string{fmt.Sprintf("SetItem|%d", pam.User)},
			wantError:   pam_test.ErrorInvalidArguments,
		},
		"Error when providing empty return values": {
			methodCalls: []cliMethodCall{{m: "SetItem", args: []any{pam.User, "an-user"}, r: []any{}}},
			args:        []string{fmt.Sprintf("SetItem|%d;an-user|", pam.User)},
			wantError:   pam_test.ErrorReturnMismatch,
		},
		"Error when not providing enough return values": {
			methodCalls: []cliMethodCall{{m: "GetItem", args: []any{pam.User}, r: []any{}}},
			args: []string{
				fmt.Sprintf("GetItem|%d|", pam.User),
			},
			wantError: pam_test.ErrorInvalidArguments,
		},
		"Error when calling unknown method": {
			methodCalls: []cliMethodCall{{m: "ThisMethodDoesNotExist"}},
			args:        []string{"ThisMethodDoesNotExist|arg"},
			wantError:   pam_test.ErrorInvalidMethod,
		},
		"Error when argument types do not match arguments": {
			methodCalls: []cliMethodCall{{m: "SetItem", args: []any{"an-item", "value"}}},
			args:        []string{"SetItem|an-item;value"},
			wantError:   pam_test.ErrorArgumentTypeMismatch,
		},
		"Error when return values types do not match expected": {
			// 'GetItem|-1|;should have been an error'
			methodCalls: []cliMethodCall{
				{m: "GetItem", args: []any{pam.Item(-1)}, r: []any{"", "should have been an error"}},
			},
			args:      []string{fmt.Sprintf("GetItem|%d|;should have been an error", pam.Item(-1))},
			wantError: pam_test.ErrorReturnMismatch,
		},
		"Error when trying to compare an unexpected variant value": {
			methodCalls: []cliMethodCall{{m: "GetEnvList", r: []any{"", pam.Error(0)}}},
			args:        []string{"GetEnvList||;0"},
			wantError:   pam_test.ErrorReturnMismatch,
		},
		"Error when trying to compare a not-matching variant value": {
			methodCalls: []cliMethodCall{{m: "GetEnvList", r: []any{"string", pam.Error(0)}}},
			args:        []string{fmt.Sprintf("GetEnvList||%s;0", getVariantString("string"))},
			wantError:   pam_test.ErrorReturnMismatch,
		},
		"Error when getting not-available user data": {
			methodCalls: []cliMethodCall{{m: "GetData", args: []any{"NotAvailable"}}},
			args:        []string{"GetData|NotAvailable"},
			wantError:   pam.ErrNoModuleData,
		},
	}
	for name, tc := range cliTests {
		t.Run("Client "+name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			moduleArgs := slices.Clone(baseModuleArgs)
			// FIXME: invert the logic
			if tc.methodCalls != nil {
				tc.args = methodCallsAsArgs(tc.methodCalls)
			}
			moduleArgs = append(moduleArgs, tc.args...)
			tx := preparePamTransaction(t, libPath, moduleArgs, "")
			require.ErrorIs(t, tx.Authenticate(0), tc.wantError)
		})
	}

	// These tests are checking Get/Set item and ensuring those values are matching
	// both inside the client and in the calling application.
	itemsTests := map[string]struct {
		item  pam.Item
		value *string
		user  string

		wantValue    *string
		wantGetError error
		wantSetError error
	}{
		"Set user": {
			item:  pam.User,
			value: ptrValue("an user"),
		},

		"Returns empty when getting an unset user": {
			item:      pam.User,
			wantValue: ptrValue(""),
		},

		"Returns the user when getting a preset user": {
			item:      pam.User,
			user:      "preset PAM user",
			wantValue: ptrValue("preset PAM user"),
		},

		"Setting and getting an user": {
			item:      pam.User,
			value:     ptrValue("the-user"),
			wantValue: ptrValue("the-user"),
		},

		// Error cases
		"Error when setting invalid item": {
			item:         pam.Item(-1),
			value:        ptrValue("some value"),
			wantSetError: pam.ErrBadItem,
		},

		"Error when getting invalid item": {
			item:         pam.Item(-1),
			wantGetError: pam.ErrBadItem,
			wantValue:    ptrValue(""),
		},
	}
	for name, tc := range itemsTests {
		t.Run("Item "+name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			moduleArgs := slices.Clone(baseModuleArgs)
			var methodCalls []cliMethodCall
			var wantExitError error

			if tc.value != nil {
				arg := fmt.Sprintf("SetItem|%d;%s", tc.item, *tc.value)
				methodCalls = append(methodCalls,
					cliMethodCall{m: "SetItem", args: []any{tc.item, *tc.value}})
				moduleArgs = append(moduleArgs, arg)
				wantExitError = tc.wantSetError
			}

			if tc.wantValue != nil {
				arg := fmt.Sprintf("GetItem|%d", tc.item)
				methodCalls = append(methodCalls,
					cliMethodCall{m: "GetItem", args: []any{tc.item}})
				moduleArgs = append(moduleArgs, arg)
				wantExitError = tc.wantGetError
			}

			moduleArgs = append(slices.Clone(baseModuleArgs), methodCallsAsArgs(methodCalls)...)
			tx := preparePamTransaction(t, libPath, moduleArgs, tc.user)
			performAllPAMActions(t, tx, 0, wantExitError)

			if tc.value != nil && tc.wantSetError == nil {
				value, err := tx.GetItem(tc.item)
				require.Equal(t, *tc.value, value, "Item %v value mismatch", tc.item)
				require.NoError(t, err, "Can't get a PAM item %v", tc.item)
			}

			if tc.wantValue != nil && tc.wantGetError == nil {
				value, err := tx.GetItem(tc.item)
				require.Equal(t, *tc.wantValue, value, "Item %v value mismatch", tc.item)
				require.NoError(t, err, "Can't get a PAM item %v", tc.item)
			}
		})
	}

	// These tests are checking that setting and unsetting env variables works
	// both inside the executed module and the caller one.
	envTests := map[string]struct {
		env          string
		value        *string
		presetValues map[string]string
		skipPut      bool

		wantValue    *string
		wantPutError pam.Error
	}{
		"Put var": {
			env:   "AN_ENV",
			value: ptrValue("value"),
		},

		"Unset a not-previously set value": {
			env:          "NEVER_SET_ENV",
			wantPutError: pam.ErrBadItem,
			wantValue:    ptrValue(""),
		},

		"Unset a preset value": {
			presetValues: map[string]string{"PRESET_ENV": "hey!"},
			env:          "PRESET_ENV",
			wantValue:    ptrValue(""),
		},

		"Changes a preset var": {
			presetValues: map[string]string{"PRESET_ENV": "hey!"},
			env:          "PRESET_ENV",
			value:        ptrValue("hello!"),
			wantValue:    ptrValue("hello!"),
		},

		"Get an unset env": {
			skipPut:   true,
			env:       "AN_UNSET_ENV",
			wantValue: ptrValue(""),
		},

		"Gets an invalid env name": {
			env:       "",
			value:     ptrValue("Invalid Value"),
			wantValue: ptrValue(""),
			skipPut:   true,
		},

		// Error cases
		"Error when putting an invalid env name": {
			env:          "",
			value:        ptrValue("Invalid Value"),
			wantPutError: pam.ErrBadItem,
		},
	}
	for name, tc := range envTests {
		t.Run("Env "+name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			var methodCalls []cliMethodCall
			wantEnvList := map[string]string{}
			moduleArgs := slices.Clone(baseModuleArgs)
			moduleArgs = append(moduleArgs,
				fmt.Sprintf("GetEnvList||%s;0", getVariantString(wantEnvList)))

			if tc.presetValues != nil && !tc.skipPut {
				for env, value := range tc.presetValues {
					methodCalls = append(methodCalls, cliMethodCall{
						m: "PutEnv", args: []any{fmt.Sprintf("%s=%s", env, value)}, r: []any{pam.Error(0)},
					})
					moduleArgs = append(moduleArgs,
						fmt.Sprintf("PutEnv|%s=%s|0", env, value))
				}
				wantEnvList = maps.Clone(tc.presetValues)
				methodCalls = append(methodCalls, cliMethodCall{
					m: "GetEnvList", r: []any{maps.Clone(wantEnvList), pam.Error(0)},
				})
				moduleArgs = append(moduleArgs,
					fmt.Sprintf("GetEnvList||%s;0", getVariantString(wantEnvList)))

				// TODO: Actually call another operation here with different arguments and
				// ensure that we set those env variables everywhere.
			}

			if !tc.skipPut {
				var env string
				if tc.value != nil {
					env = tc.env + "=" + *tc.value
				} else {
					env = tc.env
				}
				moduleArgs = append(moduleArgs,
					fmt.Sprintf("PutEnv|%s|%d", env, tc.wantPutError))
				methodCalls = append(methodCalls, cliMethodCall{
					m: "PutEnv", args: []any{env}, r: []any{tc.wantPutError},
				})

				if tc.wantPutError == pam.Error(0) {
					if tc.value != nil {
						wantEnvList[tc.env] = *tc.value
					}
					if tc.value != nil && tc.wantValue != nil {
						wantEnvList[tc.env] = *tc.wantValue
					}
					if tc.value == nil {
						delete(wantEnvList, tc.env)
					}
				}
				moduleArgs = append(moduleArgs,
					fmt.Sprintf("GetEnvList||%s;0", getVariantString(wantEnvList)))
				methodCalls = append(methodCalls, cliMethodCall{
					m: "GetEnvList", r: []any{maps.Clone(wantEnvList), pam.Error(0)},
				})
			}

			if tc.wantValue != nil {
				moduleArgs = append(moduleArgs,
					fmt.Sprintf("GetEnv|%s|%s", getVariantString(tc.env), getVariantString(*tc.wantValue)))
				methodCalls = append(methodCalls, cliMethodCall{
					m: "GetEnv", args: []any{tc.env}, r: []any{*tc.wantValue},
				})
			}

			moduleArgs = nil
			moduleArgs = append(slices.Clone(baseModuleArgs), methodCallsAsArgs(methodCalls)...)
			tx := preparePamTransaction(t, libPath, moduleArgs, "")
			envList, err := tx.GetEnvList()
			require.NoError(t, err, "Setup: GetEnvList should not return an error")
			require.Len(t, envList, 0, "Setup: GetEnvList should have elements")

			require.NoError(t, tx.AcctMgmt(0), "Calling AcctMgmt should not error")

			gotEnv, err := tx.GetEnvList()
			require.NoError(t, err, "tx.GetEnvList should not return an error")
			require.Equal(t, wantEnvList, gotEnv, "returned env lits should match expected")
		})
	}

	dataTests := map[string]struct {
		key        string
		data       any
		presetData map[string]any
		skipSet    bool
		skipGet    bool

		wantData     any
		wantSetError pam.Error
		wantGetError pam.Error
	}{
		"Sets and gets data": {
			presetData: map[string]any{"some-data": []string{"hey! That's", "true"}},
			key:        "data",
			data:       []string{"hey! That's", "true"},
			wantData:   []string{"hey! That's", "true"},
		},

		"Set replaces data": {
			presetData: map[string]any{"some-data": []string{"hey! That's", "true"}},
			key:        "some-data",
			data: []map[string]string{
				{"hey": "yay"},
				{"foo": "bar"},
			},
			wantData: []map[string]string{
				{"hey": "yay"},
				{"foo": "bar"},
			},
		},

		// Error cases
		"Error when getting data that has never been set": {
			skipSet:      true,
			key:          "not set",
			wantGetError: pam.ErrNoModuleData,
		},

		"Error when getting data that has been removed": {
			presetData:   map[string]any{"some-data": []string{"hey! That's", "true"}},
			key:          "some-data",
			data:         nil,
			wantGetError: pam.ErrNoModuleData,
		},
	}
	for name, tc := range dataTests {
		t.Run("Data "+name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			var methodCalls []cliMethodCall
			moduleArgs := slices.Clone(baseModuleArgs)

			if tc.presetData != nil && !tc.skipSet {
				for key, value := range tc.presetData {
					moduleArgs = append(moduleArgs,
						fmt.Sprintf("SetData|%s;%s", key, getVariantString(value)),
					)
					methodCalls = append(methodCalls, cliMethodCall{
						m: "SetData", args: []any{key, value},
					})
				}

				// TODO: Check those values are still valid for other action
			}

			if !tc.skipSet {
				moduleArgs = append(moduleArgs,
					fmt.Sprintf("SetData|%s;%s|%d", tc.key, getVariantString(tc.data), tc.wantSetError),
				)
				methodCalls = append(methodCalls, cliMethodCall{
					"SetData", []any{tc.key, tc.data}, []any{tc.wantSetError},
				})
			}

			if !tc.skipGet {
				moduleArgs = append(moduleArgs,
					fmt.Sprintf("GetData|%s|%s;%d", tc.key, getVariantString(tc.wantData), tc.wantGetError),
				)
				methodCalls = append(methodCalls, cliMethodCall{
					"GetData", []any{tc.key}, []any{tc.wantData, tc.wantGetError},
				})
			}

			moduleArgs = nil
			moduleArgs = append(slices.Clone(baseModuleArgs), methodCallsAsArgs(methodCalls)...)
			tx := preparePamTransaction(t, libPath, moduleArgs, "")
			require.NoError(t, tx.Authenticate(0))
		})
	}
}

func ptrValue[T any](value T) *T {
	return &value
}

func preparePamTransaction(t *testing.T, libPath string, moduleArgs []string, user string) *pam.Transaction {
	t.Helper()

	// libpam won't ever return a pam.ErrIgnore, so we use a fallback error.
	// We use incomplete here, but it could be any.
	const ignoreError = pam.ErrIncomplete
	const pamDebugIgnoreError = "incomplete"

	serviceFile := createServiceFile(t, "exec-module", libPath, moduleArgs,
		pamDebugIgnoreError)

	cnt, err := os.ReadFile(serviceFile)
	fmt.Println("Service file content")
	fmt.Println(string(cnt), err)

	tx, err := pam.StartConfDir(filepath.Base(serviceFile), user, nil, filepath.Dir(serviceFile))
	require.NoError(t, err, "PAM: Error to initialize module")
	require.NotNil(t, tx, "PAM: Transaction is not set")
	t.Cleanup(func() { require.NoError(t, tx.End(), "PAM: can't end transaction") })

	return tx
}

func performAllPAMActions(t *testing.T, tx *pam.Transaction, flags pam.Flags, wantError error) {
	t.Helper()

	t.Run("Authenticate", func(t *testing.T) { require.ErrorIs(t, tx.Authenticate(flags), wantError) })
	t.Run("AcctMgmt", func(t *testing.T) { require.ErrorIs(t, tx.AcctMgmt(flags), wantError) })
	t.Run("ChangeAuthTok", func(t *testing.T) { require.ErrorIs(t, tx.ChangeAuthTok(flags), wantError) })
	t.Run("SetCred", func(t *testing.T) { require.ErrorIs(t, tx.SetCred(flags), wantError) })
	t.Run("Open and Close Session", func(t *testing.T) {
		require.ErrorIs(t, tx.OpenSession(flags), wantError)
		require.ErrorIs(t, tx.CloseSession(flags), wantError)
	})

	// require.ErrorIs(t, tx.Authenticate(flags), wantError)
	// require.ErrorIs(t, tx.AcctMgmt(flags), wantError)
	// require.ErrorIs(t, tx.ChangeAuthTok(flags), wantError)
	// require.ErrorIs(t, tx.SetCred(flags), wantError)
	// require.ErrorIs(t, tx.OpenSession(flags), wantError)
	// require.ErrorIs(t, tx.CloseSession(flags), wantError)
}

func getVariantString(value any) string {
	if value == nil {
		return "<@mv nothing>"
	}

	variant := dbus.MakeVariant(value)
	return dbus.MakeVariantWithSignature(variant, dbus.ParseSignatureMust("v")).String()
}

func buildExecClient(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("go", "build", "-C", "cmd/exec-client")
	// cmd := exec.Command("go", "build")
	// cmd.Dir = "cmd/exec-client"
	if testutils.CoverDir() != "" {
		// -cover is a "positional flag", so it needs to come right after the "build" command.
		cmd.Args = append(cmd.Args, "-cover")
	}
	cmd.Args = append(cmd.Args, "-gcflags=-dwarflocationlists=true")
	cmd.Env = append(os.Environ(), `CGO_CFLAGS=-O0 -g3`)
	if pam_test.IsAddressSanitizerActive() {
		cmd.Args = append(cmd.Args, "-asan")
	}

	execPath := filepath.Join(t.TempDir(), "exec-client")
	t.Logf("Compiling Exec client at %s", execPath)
	t.Logf(strings.Join(cmd.Args, " "))

	cmd.Args = append(cmd.Args, "-o", execPath)
	// cmd.Args = append(cmd.Args, "-tags=pam_debug", "-o", execPath)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Setup: could not compile PAM exec client: %s", out)

	//nolint: gosec // We need to run this file and we control its sources.
	// require.NoError(t, os.Chmod(execPath, 0700), "Setup: Impossible to give execution bit to client")

	return execPath
}
