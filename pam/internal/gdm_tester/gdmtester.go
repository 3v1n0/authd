package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/brokers/responses"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/gdm"
	"github.com/ubuntu/authd/pam/internal/proto"
)

// var (
// 	socketPath = flag.String("socket-path", "", "the socket path")
// )

var currentStage proto.Stage
var pollResponses = []*gdm.EventData{}
var authModes []*authd.GAMResponse_AuthenticationMode
var brokersInfos []*authd.ABResponse_BrokerInfo

func exampleHandleGdmData(gdmData *gdm.Data) (*gdm.Data, error) {
	switch gdmData.Type {
	case gdm.DataType_hello:
		return &gdm.Data{
			Type:  gdm.DataType_hello,
			Hello: &gdm.HelloData{Version: gdm.ProtoVersion},
		}, nil

	case gdm.DataType_request:
		return exampleHandleAuthDRequest(gdmData)

	case gdm.DataType_poll:
		responses := pollResponses
		pollResponses = nil
		return &gdm.Data{
			Type:         gdm.DataType_pollResponse,
			PollResponse: responses,
		}, nil

	case gdm.DataType_event:
		err := exampleHandleEvent(gdmData.Event.Data)
		if err != nil {
			return nil, err
		}
		return &gdm.Data{
			Type: gdm.DataType_eventAck,
		}, nil
	}

	return nil, fmt.Errorf("unhandled protocol message %s",
		gdmData.Type.String())
}

func exampleHandleEvent(event gdm.Event) error {
	switch ev := event.(type) {
	case *gdm.EventData_BrokersReceived:
		if len(ev.BrokersReceived.BrokersInfos) == 0 {
			return errors.New("no brokers available")
		}
		brokersInfos = ev.BrokersReceived.BrokersInfos
		pollResponses = append(pollResponses, &gdm.EventData{
			Type: gdm.EventType_brokerSelected,
			Data: &gdm.EventData_BrokerSelected{
				BrokerSelected: &gdm.Events_BrokerSelected{
					BrokerId: brokersInfos[1].Id,
				},
			},
		})

	case *gdm.EventData_BrokerSelected:
		idx := slices.IndexFunc(brokersInfos, func(broker *authd.ABResponse_BrokerInfo) bool {
			return broker.Id == ev.BrokerSelected.BrokerId
		})
		if idx < 0 {
			return fmt.Errorf("unknown auth mode type: %s", ev.BrokerSelected.BrokerId)
		}
		log.Infof(context.TODO(), "Using broker %q", brokersInfos[idx].Name)

	case *gdm.EventData_AuthModesReceived:
		authModes = ev.AuthModesReceived.AuthModes

	case *gdm.EventData_AuthModeSelected:
		idx := slices.IndexFunc(authModes, func(mode *authd.GAMResponse_AuthenticationMode) bool {
			return mode.Id == ev.AuthModeSelected.AuthModeId
		})
		if idx < 0 {
			return fmt.Errorf("unknown auth mode type: %s", ev.AuthModeSelected.AuthModeId)
		}

	case *gdm.EventData_UiLayoutReceived:
		layout := ev.UiLayoutReceived.UiLayout
		if layout.Label != nil {
			log.Infof(context.TODO(), "%s:", *layout.Label)
		}

	case *gdm.EventData_AuthEvent:
		if msg := ev.AuthEvent.Response.Msg; msg != "" {
			var msgData map[string]any
			if err := json.Unmarshal([]byte(msg), &msgData); err != nil {
				return err
			}
			if msg, ok := msgData["message"]; ok {
				log.Infof(context.TODO(), "Got message: %s", msg)
			}
		}
		if ev.AuthEvent.Response.Access == responses.AuthGranted {
			return nil
		}
		if ev.AuthEvent.Response.Access == responses.AuthDenied {
			return nil
		}
		if ev.AuthEvent.Response.Access == responses.AuthRetry {
			pollResponses = append(pollResponses, &gdm.EventData{
				Type: gdm.EventType_isAuthenticatedRequested,
				Data: &gdm.EventData_IsAuthenticatedRequested{
					IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
						AuthenticationData: &authd.IARequest_AuthenticationData{
							Item: &authd.IARequest_AuthenticationData_Challenge{
								Challenge: "goodpass",
							},
						},
					},
				},
			})
			return nil
		}

	case *gdm.EventData_StartAuthentication:
		pollResponses = append(pollResponses, &gdm.EventData{
			Type: gdm.EventType_isAuthenticatedRequested,
			Data: &gdm.EventData_IsAuthenticatedRequested{
				IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
					AuthenticationData: &authd.IARequest_AuthenticationData{
						Item: &authd.IARequest_AuthenticationData_Challenge{
							Challenge: "wrong-pass",
						},
					},
				},
			},
		})
	}
	return nil
}

func exampleHandleAuthDRequest(gdmData *gdm.Data) (*gdm.Data, error) {
	switch req := gdmData.Request.Data.(type) {
	case *gdm.RequestData_UiLayoutCapabilities:
		required, _ := "required", "optional"
		supportedEntries := "optional:chars,chars_password"
		// requiredWithBooleans := "required:true,false"
		optionalWithBooleans := "optional:true,false"

		return &gdm.Data{
			Type: gdm.DataType_response,
			Response: &gdm.ResponseData{
				Type: gdmData.Request.Type,
				Data: &gdm.ResponseData_UiLayoutCapabilities{
					UiLayoutCapabilities: &gdm.Responses_UiLayoutCapabilities{
						SupportedUiLayouts: []*authd.UILayout{
							{
								Type:  "form",
								Label: &required,
								Entry: &supportedEntries,
								Wait:  &optionalWithBooleans,
								// Button: &optional,
							},
							{
								Type:  "newpassword",
								Label: &required,
								Entry: &supportedEntries,
								// Button: &optional,
							},
						},
					},
				},
			},
		}, nil

	case *gdm.RequestData_ChangeStage:
		if gdmData.Request.Data == nil {
			return nil, fmt.Errorf("missing stage data")
		}
		currentStage = req.ChangeStage.Stage
		log.Debugf(context.TODO(), "Switching to stage %d", currentStage)

		return &gdm.Data{
			Type: gdm.DataType_response,
			Response: &gdm.ResponseData{
				Type: gdmData.Request.Type,
				Data: &gdm.ResponseData_Ack{},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown request type")
	}
}

// LoadModule compiles and loads a pam module.
func LoadModule(socketPath string, userName string) (*pam.Transaction, error) {
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
	buildArgs := []string{
		"build",
		"-C", filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "pam"),
		"-buildmode=c-shared",
		"-o", libPath, `-gcflags=-dwarflocationlists=true`,
	}
	if isAddressSanitizerActive() {
		buildArgs = append(buildArgs, "-asan")
	}

	// #nosec:G204 - we control the command arguments in tests
	cmd := exec.Command("go", buildArgs...)
	cmd.Dir = filepath.Dir(currentFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("can't build pam module %v: %s", err, out)
	}

	serviceName := "module-loader"
	serviceFile := filepath.Join(servicePath, serviceName)
	log.Debugf(context.TODO(), "Creating service file at %s", serviceFile)

	if err := os.WriteFile(serviceFile,
		[]byte(fmt.Sprintf("auth requisite %s socket=%s", libPath, socketPath)),
		0600); err != nil {
		return nil, fmt.Errorf("can't create service file %v", err)
	}

	tx, err := pam.StartConfDir(serviceName, userName, gdm.DataConversationFunc(
		func(inData *gdm.Data) (*gdm.Data, error) {
			outData, err := exampleHandleGdmData(inData)
			if err != nil {
				return nil, err
			}
			if inData.Type == gdm.DataType_poll && len(outData.PollResponse) == 0 {
				return outData, err
			}
			json, err := inData.JSON()
			if err != nil {
				return nil, err
			}
			log.Debug(context.TODO(), "->", string(json))
			json, err = outData.JSON()
			if err != nil {
				return nil, err
			}
			log.Debug(context.TODO(), "<-", string(json))
			return outData, nil
		}), servicePath)
	if err != nil {
		return nil, fmt.Errorf("can't create PAM handler: %v", err)
	}

	log.Debug(context.TODO(), "PAM Handler created")

	return tx, nil
}

func startAuthentication() error {
	tx, err := LoadModule("/tmp/authd.sock", "")
	if err != nil {
		return err
	}

	err = tx.SetItem(pam.User, "user1")
	if err != nil {
		return err
	}

	return tx.Authenticate(pam.Flags(0))
}

func main() {
	// TODO: Add option to simulate different loading types
	log.SetLevel(log.DebugLevel)

	gdm.AdvertisePamExtensions([]string{gdm.PamExtensionCustomJSON})

	if err := startAuthentication(); err != nil {
		log.Error(context.TODO(), err)
		var pamError pam.Error
		if errors.Is(err, &pamError) {
			os.Exit(int(pamError))
		}
		os.Exit(1)
	}

	os.Exit(0)
}
