package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/msteinert/pam/v2"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/log"
	"github.com/ubuntu/authd/pam/internal/adapter"
	"github.com/ubuntu/authd/pam/internal/gdm"
	"github.com/ubuntu/authd/pam/internal/pam_test"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

type gdmClient struct {
	username        string
	lang            string
	currentBrokerID string
	currentAuthMode string
	privateKey      *rsa.PrivateKey
}

var _ authd.PAMClient = &gdmClient{}

func ptrValue[T any](value T) *T {
	return &value
}

// AvailableBrokers simulates AvailableBrokers through gdm protocol.
func (gc *gdmClient) AvailableBrokers(ctx context.Context, in *authd.Empty, opts ...grpc.CallOption) (
	*authd.ABResponse, error) {
	return &authd.ABResponse{
		BrokersInfos: []*authd.ABResponse_BrokerInfo{
			{
				Id:        "testBroker",
				Name:      "The best broker!",
				BrandIcon: nil,
			},
		},
	}, nil
}

// GetPreviousBroker simulates GetPreviousBroker through gdm protocol.
func (gc *gdmClient) GetPreviousBroker(ctx context.Context, in *authd.GPBRequest, opts ...grpc.CallOption) (
	*authd.GPBResponse, error) {
	return &authd.GPBResponse{PreviousBroker: ptrValue("testBroker")}, nil
	// FIXME: If this happens, or is empty... No broker selection will start!
	// return &authd.GPBResponse{}, nil
	// return nil, errors.New("not implemented")
}

// SelectBroker simulates SelectBroker through gdm protocol.
func (gc *gdmClient) SelectBroker(ctx context.Context, in *authd.SBRequest, opts ...grpc.CallOption) (
	*authd.SBResponse, error) {
	fmt.Println("Session requested!")
	gc.username = in.Username
	gc.currentBrokerID = in.BrokerId
	gc.lang = in.Lang
	pubASN1, err := x509.MarshalPKIXPublicKey(&gc.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &authd.SBResponse{
		SessionId:     "session-id-" + gc.currentBrokerID,
		EncryptionKey: base64.StdEncoding.EncodeToString(pubASN1),
	}, nil
}

// GetAuthenticationModes simulates GetAuthenticationModes through gdm protocol.
func (gc *gdmClient) GetAuthenticationModes(ctx context.Context, in *authd.GAMRequest, opts ...grpc.CallOption) (
	*authd.GAMResponse, error) {
	fmt.Println("We're at GetAuthenticationModes")
	return &authd.GAMResponse{
		AuthenticationModes: []*authd.GAMResponse_AuthenticationMode{
			{
				Id:    "password",
				Label: "Password authentication",
			},
		},
	}, nil
	// return nil, errors.New("not implemented")
}

// SelectAuthenticationMode simulates SelectAuthenticationMode through gdm protocol.
func (gc *gdmClient) SelectAuthenticationMode(ctx context.Context, in *authd.SAMRequest, opts ...grpc.CallOption) (
	*authd.SAMResponse, error) {
	fmt.Println("We're at SelectAuthenticationMode")
	gc.currentAuthMode = in.AuthenticationModeId
	return &authd.SAMResponse{
		UiLayoutInfo: &authd.UILayout{
			Type:  "form",
			Label: ptrValue("Gimme your password"),
			Entry: ptrValue("chars_password"),
		},
	}, nil
}

// IsAuthenticated simulates IsAuthenticated through gdm protocol.
func (gc *gdmClient) IsAuthenticated(ctx context.Context, in *authd.IARequest, opts ...grpc.CallOption) (
	*authd.IAResponse, error) {
	challenge := in.AuthenticationData.GetChallenge()
	if challenge == "" {
		return nil, errors.New("not implemented")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return nil, err
	}

	plaintext, err := rsa.DecryptOAEP(sha512.New(), nil, gc.privateKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if string(plaintext) != "foobar" {
		return &authd.IAResponse{
			Access: "retry",
		}, nil
	}

	return &authd.IAResponse{
		Access: "granted",
	}, nil
}

// EndSession simulates EndSession through gdm protocol.
func (gc *gdmClient) EndSession(ctx context.Context, in *authd.ESRequest, opts ...grpc.CallOption) (
	*authd.Empty, error) {
	fmt.Println("We're at EndSession")
	return &authd.Empty{}, nil
}

// SetDefaultBrokerForUser simulates SetDefaultBrokerForUser through gdm protocol.
func (gc *gdmClient) SetDefaultBrokerForUser(ctx context.Context, in *authd.SDBFURequest, opts ...grpc.CallOption) (
	*authd.Empty, error) {
	fmt.Println("We're at SetDefaultBrokerForUser")
	return nil, errors.New("not implemented")
}

// newClient returns a new GRPC client ready to emit requests.
func newClient(socket string) (client authd.PAMClient, close func(), err error) {
	conn, err := grpc.Dial("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("could not connect to authd: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()
	for conn.GetState() != connectivity.Ready {
		if !conn.WaitForStateChange(waitCtx, conn.GetState()) {
			conn.Close()
			return nil, func() {}, fmt.Errorf("could not connect to authd: %w", waitCtx.Err())
		}
	}
	return authd.NewPAMClient(conn), func() { conn.Close() }, nil
}

type gdmConvHandler struct{}

func (c *gdmConvHandler) RespondPAM(style pam.Style, prompt string) (string, error) {
	switch style {
	case pam.TextInfo:
		fmt.Fprintf(os.Stderr, "GDM PAM Info Message: %s\n", prompt)
	case pam.ErrorMsg:
		fmt.Fprintf(os.Stderr, "GDM PAM Error Message: %s\n", prompt)
	default:
		return "", fmt.Errorf("PAM style %d not implemented", style)
	}
	return "", nil
}

func (c *gdmConvHandler) RespondPAMBinary(ptr pam.BinaryPointer) (pam.BinaryPointer, error) {
	json, err := gdm.DecodeJSONProtoMessage(ptr)
	if err != nil {
		return nil, err
	}
	fmt.Println("->", string(json))
	gdmData, err := gdm.NewDataFromJSON(json)
	if err != nil {
		return nil, err
	}
	gdmData, err = handleGdmData(gdmData)
	if err != nil {
		return nil, err
	}
	fmt.Println("<-", string(json))
	json, err = gdmData.JSON()
	if err != nil {
		return nil, err
	}
	return gdm.NewBinaryJSONProtoResponse(json)
}

func handleGdmData(gdmData *gdm.Data) (*gdm.Data, error) {
	log.Debugf(context.TODO(), "Handling authd protocol: %#v", gdmData)

	switch gdmData.Type {
	case gdm.DataType_hello:
		return &gdm.Data{
			Type:  gdm.DataType_hello,
			Hello: &gdm.HelloData{Version: gdm.ProtoVersion},
		}, nil

	case gdm.DataType_request:
		return exampleHandleAuthDRequest(gdmData)

	case gdm.DataType_poll:
		return &gdm.Data{
			Type:         gdm.DataType_pollResponse,
			PollResponse: []*gdm.EventData{},
		}, nil

	case gdm.DataType_event:
		return &gdm.Data{
			Type: gdm.DataType_eventAck,
		}, nil
	}

	return nil, fmt.Errorf("unhandled protocol message %s",
		gdmData.Type.String())
}

func exampleHandleAuthDRequest(gdmData *gdm.Data) (*gdm.Data, error) {
	switch gdmData.Request.Type {
	case gdm.RequestType_uiLayoutCapabilities:
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
							// {
							// 	Type:  "newpassword",
							// 	Label: &required,
							// 	Entry: &supportedEntries,
							// 	// Button: &optional,
							// },
						},
					},
				},
			},
		}, nil

	case gdm.RequestType_changeStage:
		if gdmData.Request.Data == nil {
			return nil, fmt.Errorf("missing stage data")
		}
		s := gdmData.Request.Data.(*gdm.RequestData_ChangeStage).ChangeStage.Stage
		log.Debugf(context.TODO(), "Switching to stage %d", s)

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

func startGdmModel() error {
	convHandler := gdmConvHandler{}
	mTx := pam_test.NewModuleTransactionDummy(&convHandler)

	client, closeConn, err := newClient("/tmp/authd.sock")
	if err != nil {
		return err
	}
	defer closeConn()

	appState := adapter.UIModel{
		PamMTx:     mTx,
		Client:     client,
		ClientType: adapter.Gdm,
	}

	// fmt.Printf("%#v\n", appState)

	teaOpts := []tea.ProgramOption{tea.WithInput(nil), tea.WithoutRenderer()}
	p := tea.NewProgram(&appState, teaOpts...)
	if _, err := p.Run(); err != nil {
		log.Errorf(context.TODO(), "Cancelled authentication: %v", err)
		return err
	}

	fmt.Printf("GDM Module done, exit status is %#v\n", appState.ExitStatus())
	switch exitStatus := appState.ExitStatus().(type) {
	case adapter.PamReturnError:
		log.Errorf(context.TODO(), "%v: %s", exitStatus.Status(), exitStatus.Message())
		return exitStatus.Status()
	}

	return nil
}

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("could not create an valid rsa key: %v", err))
	}

	client := &gdmClient{
		privateKey: privateKey,
	}
	mTx := pam_test.NewModuleTransactionDummy(pam.ConversationFunc(
		func(style pam.Style, msg string) (string, error) {
			switch style {
			case pam.TextInfo:
				fmt.Fprintf(os.Stderr, "PAM Info Message: %s\n", msg)
			case pam.ErrorMsg:
				fmt.Fprintf(os.Stderr, "PAM Error Message: %s\n", msg)
			default:
				return "", fmt.Errorf("PAM style %d not implemented", style)
			}
			return "", nil
		}))

	appState := adapter.UIModel{
		PamMTx:     mTx,
		Client:     client,
		ClientType: adapter.InteractiveTerminal,
	}

	// if err := mTx.SetItem(pam.User, "user1"); err != nil {
	// 	log.Errorf(context.TODO(), "Cancelled authentication: %v", err)
	// 	os.Exit(1)
	// }

	// fmt.Printf("%#v\n", appState)

	var teaOpts []tea.ProgramOption
	p := tea.NewProgram(&appState, teaOpts...)
	if _, err := p.Run(); err != nil {
		log.Errorf(context.TODO(), "Cancelled authentication: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Module done, exit status is %#v\n", appState.ExitStatus())
	switch exitStatus := appState.ExitStatus().(type) {
	case adapter.PamSuccess:
		os.Exit(0)

	case adapter.PamReturnError:
		log.Errorf(context.TODO(), "%v: %s", exitStatus.Status(), exitStatus.Message())
	}

	// if err := startGdmModel(); err != nil {
	// 	log.Error(context.TODO(), err)
	// 	os.Exit(1)
	// }
}
