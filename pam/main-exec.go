//go:build pam_binary_exec

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd/pam/internal/pam_test"
)

var (
	pamFlags   = flag.Int64("flags", 0, "pam flags")
	connection = flag.String("server-address", "", "the dbus connection to use to communicate with module")
)

type moduleTransactionHandler struct {
	pam.ModuleTransaction
	conn *dbus.Conn
	obj  dbus.BusObject
}

func newModuleTransactionHandler(convHandler pam.ConversationHandler, conn *dbus.Conn) pam.ModuleTransaction {
	obj := conn.Object("com.ubuntu.authd.pam", "/com/ubuntu/authd/pam")
	fmt.Println("OBJ", obj)
	// fmt.Println("get-ITEM", obj.Call("com.ubuntu.authd.pam.GetItem", 0, pam.User))
	return &moduleTransactionHandler{
		ModuleTransaction: pam_test.NewModuleTransactionDummy(convHandler),
		conn:              conn,
		obj:               obj,
	}
}

func dbusSetter[V any, K any](obj dbus.BusObject, method string, key K, value V) error {
	var r int
	err := obj.Call(method, dbus.FlagNoAutoStart, key, value).Store(&r)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("%w: %w", pam.ErrSystem, err)
	}
	if r != 0 {
		fmt.Println(pam.Error(r))
		return pam.Error(r)
	}
	return nil
}

func dbusUnsetter[K any](obj dbus.BusObject, method string, key K) error {
	var r int
	err := obj.Call(method, dbus.FlagNoAutoStart, key).Store(&r)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("%w: %w", pam.ErrSystem, err)
	}
	if r != 0 {
		fmt.Println(pam.Error(r))
		return pam.Error(r)
	}
	return nil
}

func dbusGetter[V any, K any](obj dbus.BusObject, method string, key K) (V, error) {
	var r int
	var v V
	err := obj.Call(method, 0, key).Store(&r, &v)
	if err != nil {
		fmt.Println(err)
		return v, fmt.Errorf("%w: %w", pam.ErrSystem, err)
	}
	if r != 0 {
		fmt.Println(pam.Error(r))
		return v, pam.Error(r)
	}
	return v, nil
}

func (m *moduleTransactionHandler) SetData(key string, data any) error {
	if data == nil {
		return dbusUnsetter(m.obj, "com.ubuntu.authd.pam.UnsetData", key)
	}
	return dbusSetter(m.obj, "com.ubuntu.authd.pam.SetData", key, dbus.MakeVariant(data))
}

func (m *moduleTransactionHandler) GetData(key string) (any, error) {
	return dbusGetter[any](m.obj, "com.ubuntu.authd.pam.GetData", key)
}

func (m *moduleTransactionHandler) SetItem(item pam.Item, value string) error {
	return dbusSetter(m.obj, "com.ubuntu.authd.pam.SetItem", item, value)
}

func (m *moduleTransactionHandler) GetItem(item pam.Item) (string, error) {
	return dbusGetter[string](m.obj, "com.ubuntu.authd.pam.GetItem", item)
}

func (m *moduleTransactionHandler) PutEnv(nameval string) error {
	fmt.Println("Called Putenv", nameval)
	if !strings.Contains(nameval, "=") {
		return dbusUnsetter(m.obj, "com.ubuntu.authd.pam.UnsetEnv", nameval)
	}
	envPair := strings.SplitN(nameval, "=", 2)
	return dbusSetter(m.obj, "com.ubuntu.authd.pam.SetEnv", envPair[0], envPair[1])
}

func (m *moduleTransactionHandler) GetEnv(name string) string {
	env, _ := dbusGetter[string](m.obj, "com.ubuntu.authd.pam.GetEnv", name)
	return env
}

func (m *moduleTransactionHandler) GetEnvList() (map[string]string, error) {
	var envMap map[string]string
	err := m.obj.Call("com.ubuntu.authd.pam.GetEnvList", dbus.FlagNoAutoStart).Store(&envMap)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	// var envMap = make(map[string]string)
	// for _, envPair := range envList {
	// 	parsedPair := strings.SplitN(envPair, "=", 1)
	// 	if len(parsedPair) == 2 {
	// 		envMap[parsedPair[0]] = parsedPair[1]
	// 	}
	// }
	return envMap, nil
}

func mainFunc() int {
	module := &pamModule{}

	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		log.Fatal("not enough arguments")
	}

	var dbusConn *dbus.Conn
	if connection != nil && *connection != "" {
		fmt.Println("Connecting to", *connection)
		// c, err := dbus.Connect(*connection)
		c, err := dbus.Dial(*connection)
		if err != nil {
			log.Fatal(err)
		}
		defer c.Close()
		if err = c.Auth(nil); err != nil {
			log.Fatal(err)
		}
		fmt.Println(c)
		dbusConn = c
	}

	mTx := newModuleTransactionHandler(pam.ConversationFunc(
		func(style pam.Style, msg string) (string, error) {
			switch style {
			case pam.TextInfo:
				fmt.Println(msg)
			case pam.ErrorMsg:
				fmt.Println(msg)
			default:
				return "", fmt.Errorf("PAM style %d not implemented", style)
			}
			return "", nil
		}), dbusConn)

	action, args := args[0], args[1:]

	var flags pam.Flags
	if pamFlags != nil {
		flags = pam.Flags(*pamFlags)
	}

	mTx.PutEnv("Fooo=bar")
	mTx.PutEnv("Bar=")
	mTx.PutEnv("Bar=Bazz")
	mTx.PutEnv("Barz=Bazz=foo")
	mTx.PutEnv("Empty=")
	fmt.Println(mTx.GetEnvList())
	env, _ := mTx.GetEnvList()
	fmt.Println(env["Empty"], "-", env["Barz"])

	var err error
	switch action {
	case "authenticate":
		err = module.Authenticate(mTx, flags, args)
	case "acct_mgmt":
		err = module.AcctMgmt(mTx, flags, args)
	case "open_session":
		err = module.OpenSession(mTx, flags, args)
	case "close_session":
		err = module.CloseSession(mTx, flags, args)
	case "chauthtok":
		err = module.ChangeAuthTok(mTx, flags, args)
	case "setcred":
		err = module.SetCred(mTx, flags, args)
	default:
		log.Fatalf("Unknown action %s", action)
	}

	if err == nil {
		return 0
	}

	var pamError pam.Error
	if !errors.As(err, &pamError) {
		return 255
	}

	return int(pamError)
}

func main() {
	os.Exit(mainFunc())
}
