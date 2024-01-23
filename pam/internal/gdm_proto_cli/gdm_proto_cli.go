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

	// brokerID      string

	gotClientSupportedLayouts chan struct{}
	clientSupportedLayouts    []*authd.UILayout

	gotAuthModes chan []*authd.GAMResponse_AuthenticationMode
	// authModes    []*authd.GAMResponse_AuthenticationMode

	gotBrokersInfos chan struct{}
	brokersInfos    []*authd.ABResponse_BrokerInfo

	previousBrokerID  *string
	gotPreviousBroker chan struct{}

	// FIXME: Reset chan on broker or mode change...
	// uiLayout    *authd.UILayout
	// gotUILayout chan struct{}

	uiLayoutChan chan *authd.UILayout

	pendingEvents []*gdm.EventData

	sessionID         string
	encryptionKey     string
	gotSessionStarted chan struct{}

	authEvent chan *authd.IAResponse
}

var _ authd.PAMClient = &gdmClient{}

func ptrValue[T any](value T) *T {
	return &value
}

// AvailableBrokers simulates AvailableBrokers through gdm protocol.
func (gc *gdmClient) AvailableBrokers(ctx context.Context, in *authd.Empty, opts ...grpc.CallOption) (
	*authd.ABResponse, error) {
	fmt.Println("We're at AvailableBrokers")
	if gc.brokersInfos == nil {
		<-gc.gotBrokersInfos
	}
	return &authd.ABResponse{BrokersInfos: gc.brokersInfos}, nil
}

// GetPreviousBroker simulates GetPreviousBroker through gdm protocol.
func (gc *gdmClient) GetPreviousBroker(ctx context.Context, in *authd.GPBRequest, opts ...grpc.CallOption) (
	*authd.GPBResponse, error) {
	fmt.Println("We're at GetPreviousBroker")
	select {
	case <-time.After(200 * time.Millisecond):
	case <-gc.gotPreviousBroker:
	}
	// if gc.previousBrokerID == nil {
	// 	<-gc.gotPreviousBroker
	// }
	return &authd.GPBResponse{PreviousBroker: gc.previousBrokerID}, nil
	// FIXME: If this happens, or is empty... No broker selection will start!
	// return &authd.GPBResponse{}, nil
	// return nil, errors.New("not implemented")
}

// SelectBroker simulates SelectBroker through gdm protocol.
func (gc *gdmClient) SelectBroker(ctx context.Context, in *authd.SBRequest, opts ...grpc.CallOption) (
	*authd.SBResponse, error) {
	fmt.Println("We're at SelectBroker")
	gc.username = in.Username
	gc.currentBrokerID = in.BrokerId
	gc.lang = in.Lang

	gc.pendingEvents = append(gc.pendingEvents,
		&gdm.EventData{
			Type: gdm.EventType_brokerSelected,
			Data: &gdm.EventData_BrokerSelected{
				BrokerSelected: &gdm.Events_BrokerSelected{BrokerId: in.BrokerId},
			},
		})

	// We use our encryption key here, so that we can decrypt the challenge value we
	// received and leave the final encryption to the gdm model.
	pubASN1, err := x509.MarshalPKIXPublicKey(&gc.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	<-gc.gotSessionStarted
	return &authd.SBResponse{
		SessionId:     gc.sessionID,
		EncryptionKey: base64.StdEncoding.EncodeToString(pubASN1),
	}, nil
	// pubASN1, err := x509.MarshalPKIXPublicKey(&gc.privateKey.PublicKey)
	// if err != nil {
	// 	return nil, err
	// }
	// return &authd.SBResponse{
	// 	SessionId:     "session-id-" + gc.currentBrokerID,
	// 	EncryptionKey: base64.StdEncoding.EncodeToString(pubASN1),
	// }, nil
}

// GetAuthenticationModes simulates GetAuthenticationModes through gdm protocol.
func (gc *gdmClient) GetAuthenticationModes(ctx context.Context, in *authd.GAMRequest, opts ...grpc.CallOption) (
	*authd.GAMResponse, error) {
	fmt.Println("We're at GetAuthenticationModes")
	// return &authd.GAMResponse{
	// 	AuthenticationModes: []*authd.GAMResponse_AuthenticationMode{
	// 		{
	// 			Id:    "password",
	// 			Label: "Password authentication",
	// 		},
	// 	},
	// }, nil
	gc.clientSupportedLayouts = in.SupportedUiLayouts
	gc.gotAuthModes = make(chan []*authd.GAMResponse_AuthenticationMode)
	defer close(gc.gotAuthModes)
	return &authd.GAMResponse{
		AuthenticationModes: <-gc.gotAuthModes,
	}, nil
	// return nil, errors.New("not implemented")
}

// SelectAuthenticationMode simulates SelectAuthenticationMode through gdm protocol.
func (gc *gdmClient) SelectAuthenticationMode(ctx context.Context, in *authd.SAMRequest, opts ...grpc.CallOption) (
	*authd.SAMResponse, error) {
	fmt.Println("We're at SelectAuthenticationMode")
	// fmt.Println("before wait waited, ui layout is", gc.uiLayout)
	// // uiLayout := <-gc.uiLayoutChan
	// <-gc.gotUILayout
	// // gc.mu.Lock()
	// // defer gc.mu.Unlock()
	// // time.Sleep(200 * time.Millisecond)

	gc.uiLayoutChan = make(chan *authd.UILayout)
	// defer close(gc.uiLayoutChan)
	gc.pendingEvents = append(gc.pendingEvents,
		&gdm.EventData{
			Type: gdm.EventType_authModeSelected,
			Data: &gdm.EventData_AuthModeSelected{
				AuthModeSelected: &gdm.Events_AuthModeSelected{AuthModeId: in.AuthenticationModeId},
			},
		})

	// gc.uiLayoutCond.L.Lock()
	// gc.uiLayoutCond.Wait()
	// gc.uiLayoutCond.L.Unlock()
	// fmt.Println("waited, ui layout is", gc.uiLayout)
	// fmt.Println("Returning", gc.uiLayout)
	// fmt.Println("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
	gc.currentAuthMode = in.AuthenticationModeId
	return &authd.SAMResponse{
		UiLayoutInfo: <-gc.uiLayoutChan,
	}, nil
	// return &authd.SAMResponse{
	// 	UiLayoutInfo: &authd.UILayout{
	// 		Type:  "form",
	// 		Label: ptrValue("Gimme your passworddddddddddd"),
	// 		Entry: ptrValue("chars_password"),
	// 	},
	// }, nil
}

// IsAuthenticated simulates IsAuthenticated through gdm protocol.
func (gc *gdmClient) IsAuthenticated(ctx context.Context, in *authd.IARequest, opts ...grpc.CallOption) (
	*authd.IAResponse, error) {
	fmt.Println("We're at IsAuthenticated")

	var plaintextChallenge string
	if challenge := in.AuthenticationData.GetChallenge(); challenge != "" {
		ciphertext, err := base64.StdEncoding.DecodeString(challenge)
		if err != nil {
			return nil, err
		}

		plainText, err := rsa.DecryptOAEP(sha512.New(), nil, gc.privateKey, ciphertext, nil)
		if err != nil {
			return nil, err
		}
		plaintextChallenge = string(plainText)
	}

	gc.authEvent = make(chan *authd.IAResponse)
	defer close(gc.authEvent)
	gc.pendingEvents = append(gc.pendingEvents,
		&gdm.EventData{
			Type: gdm.EventType_isAuthenticatedRequested,
			Data: &gdm.EventData_IsAuthenticatedRequested{
				IsAuthenticatedRequested: &gdm.Events_IsAuthenticatedRequested{
					Challenge: &plaintextChallenge,
					Wait:      in.AuthenticationData.Wait,
				},
			},
		})

	return <-gc.authEvent, nil
	// return nil, errors.New("not implemented")

	// if challenge == "" {
	// 	return nil, errors.New("not implemented")
	// }
	// ciphertext, err := base64.StdEncoding.DecodeString(challenge)
	// if err != nil {
	// 	return nil, err
	// }

	// plaintext, err := rsa.DecryptOAEP(sha512.New(), nil, gc.privateKey, ciphertext, nil)
	// if err != nil {
	// 	return nil, err
	// }

	// if string(plaintext) != "foobar" {
	// 	return &authd.IAResponse{
	// 		Access: "retry",
	// 	}, nil
	// }

	// return &authd.IAResponse{
	// 	Access: "granted",
	// }, nil
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

type gdmConvHandler struct {
	gc *gdmClient
}

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
	return gdm.DataConversationFunc(func(d *gdm.Data) (*gdm.Data, error) {
		return c.handleGdmData(d)
	}).RespondPAMBinary(ptr)
	// json, err := gdm.DecodeJSONProtoMessage(ptr)
	// if err != nil {
	// 	return nil, err
	// }
	// if string(json) != `{"type":"poll"}` {
	// 	fmt.Println("->", string(json))
	// }
	// gdmData, err := gdm.NewDataFromJSON(json)
	// if err != nil {
	// 	return nil, err
	// }
	// gdmData, err = c.handleGdmData(gdmData)
	// if err != nil {
	// 	return nil, err
	// }
	// json, err = gdmData.JSON()
	// if string(json) != `{"type":"pollResponse"}` {
	// 	fmt.Println("->", string(json))
	// }
	// if err != nil {
	// 	return nil, err
	// }
	// return gdm.NewBinaryJSONProtoResponse(json)
}

func (c *gdmConvHandler) handleGdmData(gdmData *gdm.Data) (*gdm.Data, error) {
	log.Debugf(context.TODO(), "Handling authd protocol: %#v", gdmData)

	switch gdmData.Type {
	case gdm.DataType_hello:
		return &gdm.Data{
			Type:  gdm.DataType_hello,
			Hello: &gdm.HelloData{Version: gdm.ProtoVersion},
		}, nil

	case gdm.DataType_request:
		return c.handleAuthDRequest(gdmData)

	case gdm.DataType_poll:
		events := c.gc.pendingEvents
		c.gc.pendingEvents = nil
		return &gdm.Data{
			Type:         gdm.DataType_pollResponse,
			PollResponse: events,
		}, nil

	case gdm.DataType_event:
		c.handleEvent(gdmData.Event)
		return &gdm.Data{
			Type: gdm.DataType_eventAck,
		}, nil
	}

	return nil, fmt.Errorf("unhandled protocol message %s",
		gdmData.Type.String())
}

func (c *gdmConvHandler) handleAuthDRequest(gdmData *gdm.Data) (*gdm.Data, error) {
	switch req := gdmData.Request.Data.(type) {
	case *gdm.RequestData_UiLayoutCapabilities:
		<-c.gc.gotClientSupportedLayouts
		return &gdm.Data{
			Type: gdm.DataType_response,
			Response: &gdm.ResponseData{
				Type: gdmData.Request.Type,
				Data: &gdm.ResponseData_UiLayoutCapabilities{
					UiLayoutCapabilities: &gdm.Responses_UiLayoutCapabilities{
						SupportedUiLayouts: c.gc.clientSupportedLayouts,
					},
				},
			},
		}, nil

	case *gdm.RequestData_ChangeStage:
		log.Debugf(context.TODO(), "Switching to stage %d", req.ChangeStage.Stage)

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

func (c *gdmConvHandler) handleEvent(event *gdm.EventData) {
	// c.gc.mu.Lock()
	// defer c.gc.mu.Unlock()

	switch ev := event.Data.(type) {
	case *gdm.EventData_BrokersReceived:
		c.gc.brokersInfos = ev.BrokersReceived.BrokersInfos
		c.gc.gotBrokersInfos <- struct{}{}

	case *gdm.EventData_BrokerSelected:
		c.gc.previousBrokerID = &ev.BrokerSelected.BrokerId
		c.gc.gotPreviousBroker <- struct{}{}

	case *gdm.EventData_AuthModesReceived:
		c.gc.gotAuthModes <- ev.AuthModesReceived.AuthModes

	case *gdm.EventData_UiLayoutReceived:
		// c.gc.uiLayout = ev.UiLayoutReceived.UiLayout
		// fmt.Println("UI LAYOUT RECEIVED!\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
		// c.gc.uiLayoutCond.Broadcast()
		// c.gc.gotUILayout <- struct{}{}
		c.gc.uiLayoutChan <- ev.UiLayoutReceived.UiLayout
		// close(c.gc.gotUILayout)
		// c.gc.gotUILayout = make(chan struct{})

	case *gdm.EventData_AuthEvent:
		c.gc.authEvent <- ev.AuthEvent.Response
	}
}

type gdmUIModel struct {
	adapter.UIModel
	gc *gdmClient
}

func (m *gdmUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	_, cmd := m.UIModel.Update(msg)

	switch msg := msg.(type) {
	case adapter.TestSessionStarted:
		m.gc.encryptionKey = msg.EncryptionKey()
		m.gc.sessionID = msg.SessionID()
		m.gc.gotSessionStarted <- struct{}{}
	}

	return m, cmd
}

func startGdmModel(gc *gdmClient) error {
	convHandler := gdmConvHandler{gc}
	mTx := pam_test.NewModuleTransactionDummy(&convHandler)

	// if err := mTx.SetItem(pam.User, "user1"); err != nil {
	// 	log.Errorf(context.TODO(), "Cancelled authentication: %v", err)
	// 	return err
	// }

	client, closeConn, err := newClient("/tmp/authd.sock")
	if err != nil {
		return err
	}
	defer closeConn()

	appState := gdmUIModel{
		UIModel: adapter.UIModel{
			PamMTx:     mTx,
			Client:     client,
			ClientType: adapter.Gdm,
		},
		gc: gc,
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

func runGdmClient(gc *gdmClient) chan error {
	c := make(chan error)
	go func() {
		err := startGdmModel(gc)
		if err != nil {
			log.Error(context.TODO(), err)
		}
		c <- err
	}()
	return c
}

type cliUIModel struct {
	adapter.UIModel
	gc *gdmClient
}

func (m *cliUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	_, cmd := m.UIModel.Update(msg)
	// log.Infof(context.TODO(), "UPDATE: %#v", msg)

	// tp := reflect.TypeOf(msg)
	// fmt.Println(tp)
	switch msg := msg.(type) {
	case adapter.TestUserSelected:
		m.gc.pendingEvents = append(m.gc.pendingEvents,
			&gdm.EventData{
				Type: gdm.EventType_userSelected,
				Data: &gdm.EventData_UserSelected{
					UserSelected: &gdm.Events_UserSelected{UserId: msg.UserName()},
				},
			})

	case adapter.TestSupportedUILayoutsReceived:
		m.gc.clientSupportedLayouts = msg.Layouts()
		close(m.gc.gotClientSupportedLayouts)

		// case adapter.TestAuthModeSelected:
		// 	m.gc.pendingEvents = append(m.gc.pendingEvents,
		// 		&gdm.EventData{
		// 			Type: gdm.EventType_authModeSelected,
		// 			Data: &gdm.EventData_AuthModeSelected{
		// 				AuthModeSelected: &gdm.Events_AuthModeSelected{AuthModeId: msg.AuthModeID()},
		// 			},
		// 		})
		// m.gc.currentAuthMode =

		// case adapter.TestBrokerSelected:
		// 	m.gc.pendingEvents = append(m.gc.pendingEvents,
		// 		&gdm.EventData{
		// 			Type: gdm.EventType_brokerSelected,
		// 			Data: &gdm.EventData_BrokerSelected{
		// 				BrokerSelected: &gdm.Events_BrokerSelected{BrokerId: msg.BrokerID()},
		// 			},
		// 		})
	}

	return m, cmd
}

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("could not create an valid rsa key: %v", err))
	}

	client := &gdmClient{
		privateKey:                privateKey,
		gotClientSupportedLayouts: make(chan struct{}),
		gotBrokersInfos:           make(chan struct{}),
		gotPreviousBroker:         make(chan struct{}),
		// gotUILayout:               make(chan struct{}),
		gotSessionStarted: make(chan struct{}),
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

	appState := cliUIModel{adapter.UIModel{
		PamMTx:     mTx,
		Client:     client,
		ClientType: adapter.InteractiveTerminal,
	}, client}

	gdmErrChan := runGdmClient(client)

	// if err := mTx.SetItem(pam.User, "user1"); err != nil {
	// 	log.Errorf(context.TODO(), "Cancelled authentication: %v", err)
	// 	os.Exit(1)
	// }

	// fmt.Printf("%#v\n", appState)

	teaOpts := []tea.ProgramOption{ /* tea.WithoutRenderer() */ }
	// teaOpts = []tea.ProgramOption{tea.WithoutRenderer()}
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
		os.Exit(1)
	}

	if err := <-gdmErrChan; err != nil {
		log.Errorf(context.TODO(), "%v", err)
		os.Exit(1)
	}

	// if err := startGdmModel(); err != nil {
	// 	log.Error(context.TODO(), err)
	// 	os.Exit(1)
	// }
}
