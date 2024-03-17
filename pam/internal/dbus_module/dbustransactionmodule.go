// package dbus includes the tool for DBus PAM module interactions.
package dbus_module

import (
	"context"
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/pam_test"
)

// ModuleTransaction is a [pam.ModuleTransaction] with dbus support.
type ModuleTransaction struct {
	pam.ModuleTransaction
	conn *dbus.Conn
	obj  dbus.BusObject
}

const ifaceName = "com.ubuntu.authd.pam"

func NewModuleTransaction(address string) (mTx pam.ModuleTransaction, cleanup func(), err error) {
	log.Debugf(context.TODO(), "Connecting to %s", address)
	// waitCtx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	// defer cancel()
	// conn, err := dbus.Dial(address, dbus.WithContext(waitCtx))
	conn, err := dbus.Dial(address)
	if err != nil {
		return nil, func() {}, err
	}
	cleanup = func() { conn.Close() }
	if err = conn.Auth(nil); err != nil {
		return nil, cleanup, err
	}
	obj := conn.Object(ifaceName, "/com/ubuntu/authd/pam")
	return &ModuleTransaction{
		ModuleTransaction: &pam_test.ModuleTransactionDummy{},
		conn:              conn,
		obj:               obj,
	}, cleanup, nil
}

// InvokeHandler is called by the C code to invoke the proper handler.
func (m *ModuleTransaction) InvokeHandler(handler pam.ModuleHandlerFunc,
	flags pam.Flags, args []string) error {
	return pam.ErrAbort
}

func dbusSetter[V any, K any](obj dbus.BusObject, method string, key K, value V) error {
	var r int
	method = fmt.Sprintf("%s.%s", ifaceName, method)
	err := obj.Call(method, dbus.FlagNoAutoStart, key, value).Store(&r)
	if err != nil {
		log.Infof(context.TODO(), "failed to call %s: %v", method, err)
		return fmt.Errorf("%w: %w", pam.ErrSystem, err)
	}
	if r != 0 {
		log.Infof(context.TODO(), "failed to call %s: %s", method, pam.Error(r))
		return pam.Error(r)
	}
	return nil
}

func dbusUnsetter[K any](obj dbus.BusObject, method string, key K) error {
	var r int
	method = fmt.Sprintf("%s.%s", ifaceName, method)
	err := obj.Call(method, dbus.FlagNoAutoStart, key).Store(&r)
	if err != nil {
		log.Infof(context.TODO(), "failed to call %s: %v", method, err)
		return fmt.Errorf("%w: %w", pam.ErrSystem, err)
	}
	if r != 0 {
		log.Infof(context.TODO(), "failed to call %s: %s", method, pam.Error(r))
		return pam.Error(r)
	}
	return nil
}

func dbusGetter[V any, K any](obj dbus.BusObject, method string, key K) (V, error) {
	var r int
	var v V
	method = fmt.Sprintf("%s.%s", ifaceName, method)
	err := obj.Call(method, 0, key).Store(&r, &v)
	if err != nil {
		log.Infof(context.TODO(), "failed to call %s: %v", method, err)
		return v, fmt.Errorf("%w: %w", pam.ErrSystem, err)
	}
	if r != 0 {
		log.Infof(context.TODO(), "failed to call %s: %s", method, pam.Error(r))
		return v, pam.Error(r)
	}
	return v, nil
}

func (m *ModuleTransaction) SetData(key string, data any) error {
	if data == nil {
		return dbusUnsetter(m.obj, "UnsetData", key)
	}
	// dataValue := reflect.ValueOf(data)
	// log.Debugf(context.TODO(), "Setting data %#v", dataValue.Kind())
	// log.Debugf(context.TODO(), "Setting data %#v", dataValue)
	// log.Debugf(context.TODO(), "Setting data %#v", data)
	// // log.Debugf(context.TODO(), "Setting data %#v", dataValue.IsNil())
	// // log.Debugf(context.TODO(), "Setting data %#v", dataValue.IsZero())
	// log.Debugf(context.TODO(), "Setting data %#v", dataValue.CanAddr() && dataValue.Addr().IsNil())
	// log.Debugf(context.TODO(), "Setting data %#v", reflect.DeepEqual(data, nil))
	// log.Debugf(context.TODO(), "Setting data %s", dataValue.Kind())
	// log.Debugf(context.TODO(), "Setting data %#v", (dataValue.Kind() == reflect.Struct && dataValue.Elem().IsNil()))
	// if asVariant, ok := data.(dbus.Variant); ok {
	// 	return dbusSetter(m.obj, "SetData", key, asVariant)
	// }
	return dbusSetter(m.obj, "SetData", key, dbus.MakeVariant(data))
}

func (m *ModuleTransaction) GetData(key string) (any, error) {
	return dbusGetter[any](m.obj, "GetData", key)
}

func (m *ModuleTransaction) SetItem(item pam.Item, value string) error {
	return dbusSetter(m.obj, "SetItem", item, value)
}

func (m *ModuleTransaction) GetItem(item pam.Item) (string, error) {
	return dbusGetter[string](m.obj, "GetItem", item)
}

func (m *ModuleTransaction) PutEnv(nameval string) error {
	fmt.Println("Called Putenv", nameval)
	if !strings.Contains(nameval, "=") {
		return dbusUnsetter(m.obj, "UnsetEnv", nameval)
	}
	envPair := strings.SplitN(nameval, "=", 2)
	return dbusSetter(m.obj, "SetEnv", envPair[0], envPair[1])
}

func (m *ModuleTransaction) GetEnv(name string) string {
	fmt.Println("Called Getenv", name)
	env, err := dbusGetter[string](m.obj, "GetEnv", name)
	if err != nil {
		log.Infof(context.TODO(), "failed to get env: %v", err)
		return ""
	}
	fmt.Println("Returning", env)
	return env
}

func (m *ModuleTransaction) GetEnvList() (map[string]string, error) {
	var envMap map[string]string
	err := m.obj.Call(ifaceName+".GetEnvList", dbus.FlagNoAutoStart).Store(&envMap)
	if err != nil {
		log.Infof(context.TODO(), "failed to call GetEnvList: %v", err)
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
