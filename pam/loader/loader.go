package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/gdm"
)

type PamMessagesHandler func(message string) (string, error)
type GdmDataHandler func(*gdm.Data) (*gdm.Data, error)

type Handlers struct {
	info,
	errorMsg,
	promptEchoOn,
	promptEchoOff PamMessagesHandler
	gdmData GdmDataHandler
}

var defaultHandlers Handlers

func RegisterHandlers(handlers Handlers) {
	defaultHandlers = handlers
}

// LoadModule compiles and loads a pam module.
func LoadModule() (pamHandle, error) {
	servicePath, err := os.MkdirTemp(os.TempDir(), "test-pam-loader-*")
	if err != nil {
		return nil, fmt.Errorf("can't create service path %v", err)
	}
	defer os.RemoveAll(servicePath)

	libPath := filepath.Join(servicePath, "libpam_authd.so")
	log.Debugf(context.TODO(), "Compiling module at %s", libPath)
	_, currentFile, _, ok := runtime.Caller(1)
	if !ok {
		return nil, errors.New("can't get current binary path")
	}
	// #nosec:G204 - we control the command arguments in tests
	cmd := exec.Command("go", "build", "-C", filepath.Join(
		filepath.Dir(currentFile), ".."), "-buildmode=c-shared", "-o",
		libPath)
	cmd.Dir = filepath.Dir(currentFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("can't build pam module %v: %s", err, out)
	}

	serviceName := "module-loader"
	serviceFile := filepath.Join(servicePath, serviceName)
	log.Debugf(context.TODO(), "Creating service file at %s", serviceFile)

	if err := os.WriteFile(serviceFile,
		[]byte(fmt.Sprintf("auth requisite %s", libPath)),
		0600); err != nil {
		return nil, fmt.Errorf("can't create service file %v", err)
	}

	advertisePamExtensions([]string{GDM_PAM_EXTENSION_PRIVATE_STRING})
	pamh, err := initPamHandle(serviceFile, "", servicePath)
	if err != nil {
		return nil, fmt.Errorf("can't create PAM handler: %v", err)
	}

	log.Debug(context.TODO(), "PAM Handler created")

	return pamh, nil
}

func StartAuthentication(handlers Handlers) (int, error) {
	RegisterHandlers(handlers)

	pamh, err := LoadModule()
	if err != nil {
		return 2, err
	}

	if ret, err := authenticate(pamh); err != nil {
		//nolint:errcheck // we have another error to return
		destroyPamHandle(pamh, ret)
		return ret, err
	}

	return destroyPamHandle(pamh, PAM_SUCCESS)
}
