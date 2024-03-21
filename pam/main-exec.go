//go:build !pam_binary_cli

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/dbusmodule"
)

var (
	pamFlags      = flag.Int64("flags", 0, "pam flags")
	serverAddress = flag.String("server-address", "", "the dbus connection to use to communicate with module")
)

func mainFunc() error {
	module := &pamModule{}

	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		return errors.New("not enough arguments")
	}

	if serverAddress == nil {
		return fmt.Errorf("%w: no connection provided", pam.ErrSystem)
	}

	mTx, closeFunc, err := dbusmodule.NewTransaction(context.TODO(), *serverAddress)
	if err != nil {
		return fmt.Errorf("%w: can't connect to server: %w", pam.ErrSystem, err)
	}
	defer closeFunc()

	action, args := args[0], args[1:]

	flags := pam.Flags(0)
	if pamFlags != nil {
		flags = pam.Flags(*pamFlags)
	}

	switch action {
	case "authenticate":
		return module.Authenticate(mTx, flags, args)
	case "acct_mgmt":
		return module.AcctMgmt(mTx, flags, args)
	case "open_session":
		return module.OpenSession(mTx, flags, args)
	case "close_session":
		return module.CloseSession(mTx, flags, args)
	case "chauthtok":
		return module.ChangeAuthTok(mTx, flags, args)
	case "setcred":
		return module.SetCred(mTx, flags, args)
	default:
		return fmt.Errorf("Unknown action %s", action)
	}
}

func main() {
	err := mainFunc()
	if err == nil {
		os.Exit(0)
	}
	var pamError pam.Error
	if !errors.As(err, &pamError) {
		log.Error(context.TODO(), err)
		os.Exit(255)
	}
	os.Exit(int(pamError))
}
