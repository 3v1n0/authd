//+go:build pam_tests

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/dbus_module"
	"github.com/ubuntu/authd/pam/internal/pam_test"
)

var (
	pamFlags      = flag.Int64("flags", 0, "pam flags")
	serverAddress = flag.String("server-address", "", "the dbus connection address to use to communicate with module")
)

func main() {
	err := mainFunc()
	if err == nil {
		log.Info(context.TODO(), "Exiting with success")
		os.Exit(0)
	}

	log.Errorf(context.TODO(), "Exiting with error: %v", err)
	var pamError pam.Error
	if !errors.As(err, &pamError) {
		os.Exit(255)
	}
	os.Exit(int(pamError))
}

func mainFunc() error {
	flag.Parse()
	args := flag.Args()

	log.SetLevel(log.DebugLevel)

	if len(args) < 1 {
		fmt.Errorf("%w: not enough arguments", pam_test.ErrorInvalid)
	}

	if serverAddress == nil {
		fmt.Errorf("%w: no connection provided", pam_test.ErrorInvalid)
	}

	mTx, closeFunc, err := dbus_module.NewModuleTransaction(*serverAddress)
	defer closeFunc()
	if err != nil {
		return fmt.Errorf("%w: can't connect to server: %w", pam_test.ErrorInvalid, err)
	}

	action, args := args[0], args[1:]
	switch action {
	case "authenticate":
		return handleArgs(mTx, args)
	case "acct_mgmt":
		return handleArgs(mTx, args)
	case "open_session":
		return handleArgs(mTx, args)
	case "close_session":
		return handleArgs(mTx, args)
	case "chauthtok":
		return handleArgs(mTx, args)
	case "setcred":
		return handleArgs(mTx, args)
	default:
		return fmt.Errorf("unknown action %s", action)
	}

	// mTx.PutEnv("Fooo=bar")
	// mTx.PutEnv("Bar=")
	// mTx.PutEnv("Bar=Bazz")
	// mTx.PutEnv("Barz=Bazz=foo")
	// mTx.PutEnv("Empty=")
	// fmt.Println(mTx.GetEnvList())
	// env, _ := mTx.GetEnvList()
	// fmt.Println(env["Empty"], "-", env["Barz"])

	// return nil
}

func handleArgs(mTx pam.ModuleTransaction, args []string) error {
	for _, arg := range args {
		err := handleArg(mTx, arg)
		if err != nil {
			return err
		}
	}
	return nil
}

func handleArg(mTx pam.ModuleTransaction, arg string) error {
	// We support handing operations such as:
	//   <Action>|<input>[|<expected-ret>]
	// Where:
	//  - <Action> is the method to call
	//  - <input> is a semicolon-separated list of arguments
	//  - <expected-ret> is an optional semicolon-separated list of expected return values
	// For example:
	// 	SetItem|2;user SetItem|-1;foo|29

	log.Debugf(context.TODO(), "Parsing argument '%v'", arg)
	splitArgs := strings.SplitN(arg, "|", 3)
	action := splitArgs[0]

	var inputArgs *string
	if len(splitArgs) > 1 && splitArgs[1] != "" {
		inputArgs = &splitArgs[1]
	}

	var expectedRet *string
	if len(splitArgs) == 3 {
		expectedRet = &splitArgs[2]
	}

	method := reflect.ValueOf(mTx).MethodByName(action)
	if method == (reflect.Value{}) {
		return fmt.Errorf("no method %s found: %w", action, pam_test.ErrorInvalidMethod)
	}

	callArgs, err := getCallArgs(action, method, inputArgs)
	if err != nil {
		return err
	}

	retValues := method.Call(callArgs)
	if expectedRet == nil {
		// If return value is not explicitly handled, we just return the error if we got one
		for _, ret := range retValues {
			if !ret.CanInterface() {
				continue
			}
			iface := ret.Interface()
			switch value := iface.(type) {
			case error:
				return value
			}
		}
		return nil
	}

	return checkReturnedValues(action, method, *expectedRet, retValues)
}

func checkConversion(wantedType reflect.Type, inputType reflect.Type) error {
	if inputType.ConvertibleTo(wantedType) {
		return nil
	}

	return fmt.Errorf("cannot convert %s to %s, %w", inputType, wantedType)
}

func tryConvertTyped[T any](arg T, expected reflect.Type) (reflect.Value, error) {
	argValue := reflect.ValueOf(arg)
	err := checkConversion(expected, argValue.Type())
	if err != nil {
		return reflect.Value{}, err
	}
	return argValue.Convert(expected), nil
}

func canBeVariant(arg string) bool {
	return len(arg) > 0 && arg[0] == '<' && arg[len(arg)-1] == '>'
}

func tryConvertString(arg string, expected reflect.Type) (reflect.Value, error) {
	if canBeVariant(arg) {
		return tryParseVariant(arg, expected)
	}

	argValue := reflect.ValueOf(arg)
	err := checkConversion(expected, argValue.Type())
	if err == nil {
		return argValue.Convert(expected), nil
	}

	switch expected.Kind() {
	case reflect.Int:
		intArg, err := strconv.Atoi(arg)
		if err != nil {
			return reflect.Value{}, err
		}
		return tryConvertTyped(intArg, expected)

	case reflect.Bool:
		boolArg, err := strconv.ParseBool(arg)
		if err != nil {
			return reflect.Value{}, err
		}
		return tryConvertTyped(boolArg, expected)
	}

	if expected.ConvertibleTo(reflect.TypeFor[error]()) {
		pamError, err := tryConvertString(arg, reflect.TypeFor[pam.Error]())
		if err != nil {
			return tryConvertTyped(errors.New(arg), expected)
		}
		if pamError.IsZero() {
			return reflect.Zero(expected), nil
		}
		return pamError, nil
	}

	return tryParseVariant(arg, expected)
}

func isVariantNothing(arg string) bool {
	if arg == "nothing" || arg == "<nothing>" {
		return true
	}

	ok, _ := regexp.MatchString("<@m[vbynqiuxthd] nothing>", arg)
	return ok
}

func tryParseVariant(arg string, expected reflect.Type) (reflect.Value, error) {
	// FIXME: go dbus.Variant doesn't support maybe types syntax... So we handle it manually.
	if isVariantNothing(arg) {
		return reflect.Zero(expected), nil
	}
	variant, err := dbus.ParseVariant(arg, dbus.ParseSignatureMust("v"))
	if err != nil {
		return reflect.Value{}, fmt.Errorf("can't convert '%s' to variant", arg)
	}
	innerValue, ok := variant.Value().(dbus.Variant)
	if !ok {
		return reflect.Value{}, fmt.Errorf("%w: can't find a variant in %v",
			pam_test.ErrorInvalid, variant)
	}
	return tryConvertTyped(innerValue.Value(), expected)
}

func getCallArgs(action string, method reflect.Value, inputArgs *string) ([]reflect.Value, error) {
	var args []string
	if inputArgs != nil {
		args = strings.Split(*inputArgs, ";")
	}
	methodType := method.Type()
	if len(args) != methodType.NumIn() {
		return nil, fmt.Errorf("method %s %s needs %d arguments (%d provided): %w",
			action, methodType, methodType.NumIn(), len(args), pam_test.ErrorInvalidArguments)
	}

	var callArgs []reflect.Value
	for idx, input := range args {
		value, err := tryConvertString(input, methodType.In(idx))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", err, pam_test.ErrorArgumentTypeMismatch)
		}

		callArgs = append(callArgs, value)
	}

	return callArgs, nil
}

func checkReturnedValues(action string, method reflect.Value, wantArgsStr string, retValues []reflect.Value) error {
	methodType := method.Type()
	wantArgs := strings.Split(wantArgsStr, ";")
	if len(wantArgs) != methodType.NumOut() || len(wantArgs) != len(retValues) {
		return fmt.Errorf("method %s %s returns %d arguments (%d provided): %w",
			action, methodType, methodType.NumOut(), len(wantArgs), pam_test.ErrorInvalidArguments)
	}

	for idx, wantArg := range wantArgs {
		wantValue, err := tryConvertString(wantArg, methodType.Out(idx))
		if err != nil {
			return fmt.Errorf("%w: %w", err, pam_test.ErrorReturnMismatch)
		}

		retValue := retValues[idx]

		// FIXME: We'd really not need this if dbus.Variant would support maybe types
		if asString, ok := retValue.Interface().(string); ok && isVariantNothing(asString) {
			retValue = reflect.Zero(wantValue.Type())
		}

		switch wantValue.Kind() {
		case reflect.Func, reflect.Map, reflect.Slice, reflect.Interface:
			if reflect.DeepEqual(retValue, wantValue) {
				continue
			}
			// Sometimes values are equal but DeepEqual doesn't think so, thus let's go wild
			if fmt.Sprintf("%#v", retValue) == fmt.Sprintf("%#v", wantValue) {
				continue
				// if !reflect.DeepEqual(wantValue, retValue) {
			}

		default:
			if retValue.Equal(wantValue) {
				continue
			}
		}

		return fmt.Errorf("values do not match: expected '%#v', got '%#v': %w",
			wantValue, retValue, pam_test.ErrorReturnMismatch)
	}

	return nil
}
