package main_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/testutils"
	grouptests "github.com/ubuntu/authd/internal/users/localgroups/tests"
	"github.com/ubuntu/authd/pam/internal/gdm"
	"github.com/ubuntu/authd/pam/internal/gdm_test"
	"github.com/ubuntu/authd/pam/internal/pam_test"
	"github.com/ubuntu/authd/pam/internal/proto"
)

func init() {
	gdm.AdvertisePamExtensions([]string{gdm.PamExtensionCustomJSON})
}

const (
	exampleBrokerName = "ExampleBroker"
	localBrokerName   = "local"
	ignoredBrokerName = "<ignored-broker>"

	passwordAuthID = "password"
	fido1AuthID    = "fidodevice1"
	phoneAck1ID    = "phoneack1"
)

func TestGdmModule(t *testing.T) {
	t.Parallel()

	// This happens when GO_WANT_HELPER_PROCESS is defined, in such case let's just skip.
	if daemonPath == "" {
		t.Skip("Test cannot run without an example daemon")
	}

	if !pam.CheckPamHasStartConfdir() {
		t.Skip("can't test with this libpam version!")
	}

	require.True(t, pam.CheckPamHasBinaryProtocol(),
		"PAM does not support binary protocol")

	gpasswdOutput := filepath.Join(t.TempDir(), "gpasswd.output")
	groupsFile := filepath.Join(testutils.TestFamilyPath(t), "gpasswd.group")

	ctx, cancel := context.WithCancel(context.Background())
	socketPath, stopped := testutils.RunDaemon(ctx, t, daemonPath,
		testutils.WithEnvironment(grouptests.GPasswdMockEnv(t, gpasswdOutput, groupsFile)...),
	)
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	libPath := buildPAMLibrary(t)
	serviceFile := createServiceFile(t, "module-loader", libPath,
		[]string{"socket=" + socketPath}, "incomplete")

	testCases := map[string]struct {
		supportedLayouts   []*authd.UILayout
		pamUser            string
		protoVersion       uint32
		brokerName         string
		authModeIDs        []string
		eventPollResponses map[gdm.EventType][]*gdm.EventData

		wantError            error
		wantPamInfoMessages  []string
		wantPamErrorMessages []string
	}{
		"Authenticates user1": {
			pamUser: "user1",
			eventPollResponses: map[gdm.EventType][]*gdm.EventData{
				gdm.EventType_startAuthentication: {
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "goodpass",
					}),
				},
			},
		},
		"Authenticates user1 with multiple retries": {
			pamUser:     "user1",
			authModeIDs: []string{passwordAuthID, passwordAuthID, passwordAuthID},
			eventPollResponses: map[gdm.EventType][]*gdm.EventData{
				gdm.EventType_startAuthentication: {
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "not goodpass",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "goodpasssss",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "goodpass",
					}),
				},
			},
		},
		"Authenticates user-mfa": {
			pamUser:     "user-mfa",
			authModeIDs: []string{passwordAuthID, fido1AuthID, phoneAck1ID},
			eventPollResponses: map[gdm.EventType][]*gdm.EventData{
				gdm.EventType_startAuthentication: {
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "goodpass",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Wait{
						Wait: "true",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Wait{
						Wait: "true",
					}),
				},
			},
		},
		"Authenticates user-mfa after retry": {
			pamUser:     "user-mfa",
			authModeIDs: []string{passwordAuthID, passwordAuthID, fido1AuthID, phoneAck1ID},
			eventPollResponses: map[gdm.EventType][]*gdm.EventData{
				gdm.EventType_startAuthentication: {
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "not goodpass",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "goodpass",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Wait{
						Wait: "true",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Wait{
						Wait: "true",
					}),
				},
			},
		},
		"Authenticates user2 after switching to phone ack": {
			pamUser:     "user2",
			authModeIDs: []string{passwordAuthID, phoneAck1ID},
			eventPollResponses: map[gdm.EventType][]*gdm.EventData{
				gdm.EventType_startAuthentication: {
					gdm_test.ChangeStageEvent(proto.Stage_authModeSelection),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Wait{
						Wait: "true",
					}),
				},
				gdm.EventType_authEvent: {
					gdm_test.AuthModeSelectedEvent(phoneAck1ID),
				},
			},
		},

		// Error cases
		"Error on unknown protocol": {
			pamUser:      "user-foo",
			protoVersion: 9999,
			wantPamErrorMessages: []string{
				"GDM protocol initialization failed, type hello, version 9999",
			},
			wantError: pam.ErrCredUnavail,
		},
		"Error on missing user": {
			pamUser: "",
			wantPamErrorMessages: []string{
				"can't select broker: rpc error: code = InvalidArgument desc = can't start authentication transaction: rpc error: code = InvalidArgument desc = no user name provided",
			},
			wantError: pam.ErrSystem,
		},
		"Error on no supported layouts": {
			pamUser:          "user-bar",
			supportedLayouts: []*authd.UILayout{},
			wantPamErrorMessages: []string{
				"UI does not support any layouts",
			},
			wantError: pam.ErrCredUnavail,
		},
		"Error on unknown broker": {
			pamUser:    "user-foo",
			brokerName: "Not a valid broker!",
			eventPollResponses: map[gdm.EventType][]*gdm.EventData{
				gdm.EventType_brokersReceived: {
					gdm_test.SelectBrokerEvent("some-unknown-broker"),
				},
			},
			wantPamErrorMessages: []string{
				"Sending GDM event failed: Conversation error",
			},
			wantError: pam.ErrSystem,
		},
		// "Error on unknown authentication mode": {
		// 	pamUser:     "invalid-auth-mode",
		// 	authModeIDs: []string{passwordAuthID, "invalid auth-id"},
		// 	eventPollResponses: map[gdm.EventType][]*gdm.EventData{
		// 		gdm.EventType_startAuthentication: {
		// 			gdm_test.ChangeStageEvent(proto.Stage_authModeSelection),
		// 		},
		// 		gdm.EventType_authEvent: {
		// 			gdm_test.AuthModeSelectedEvent("invalid auth-id"),
		// 		},
		// 	},
		// },
		"Error (ignored) on local broker causes incomplete error": {
			pamUser:    "user-foo",
			brokerName: localBrokerName,
			wantPamInfoMessages: []string{
				"auth=incomplete",
			},
			wantError: pam.ErrIncomplete,
		},
		"Error on authenticating user1 with too many retries": {
			pamUser:     "user1",
			authModeIDs: []string{passwordAuthID, passwordAuthID, passwordAuthID, passwordAuthID, passwordAuthID},
			eventPollResponses: map[gdm.EventType][]*gdm.EventData{
				gdm.EventType_startAuthentication: {
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "not goodpass",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "another not goodpass",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "even more not goodpass",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "not yet goodpass",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "really, it's not a goodpass!",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "goodpass",
					}),
				},
			},
			wantPamErrorMessages: []string{
				"invalid password, should be goodpass",
			},
			wantError: pam.ErrAuth,
		},
		"Error on authenticating unknown user": {
			pamUser: "user-unknown",
			eventPollResponses: map[gdm.EventType][]*gdm.EventData{
				gdm.EventType_startAuthentication: {
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "goodpass",
					}),
				},
			},
			wantPamErrorMessages: []string{
				"user not found",
			},
			wantError: pam.ErrAuth,
		},
		"Error on invalid fido ack": {
			pamUser:     "user-mfa",
			authModeIDs: []string{passwordAuthID, fido1AuthID},
			eventPollResponses: map[gdm.EventType][]*gdm.EventData{
				gdm.EventType_startAuthentication: {
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Challenge{
						Challenge: "goodpass",
					}),
					gdm_test.IsAuthenticatedEvent(&authd.IARequest_AuthenticationData_Wait{}),
				},
			},
			wantPamErrorMessages: []string{
				fido1AuthID + " should have wait set to true",
			},
			wantError: pam.ErrAuth,
		},
	}
	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gh := newGdmTestModuleHandler(t, serviceFile, tc.pamUser)
			gh.eventPollResponses = tc.eventPollResponses

			if tc.supportedLayouts == nil {
				gh.supportedLayouts = []*authd.UILayout{pam_test.FormUILayout()}
			}

			gh.protoVersion = gdm.ProtoVersion
			if tc.protoVersion != 0 {
				gh.protoVersion = tc.protoVersion
			}

			gh.selectedBrokerName = tc.brokerName
			if gh.selectedBrokerName == "" {
				gh.selectedBrokerName = exampleBrokerName
			}

			gh.selectedAuthModeIDs = tc.authModeIDs
			if gh.selectedAuthModeIDs == nil {
				gh.selectedAuthModeIDs = []string{passwordAuthID}
			}

			authResult := make(chan error)
			go func() {
				authResult <- gh.tx.Authenticate(pam.Flags(0))
			}()

			select {
			case <-time.After(10 * time.Second):
				t.Fatal("Authentication timed out!")
			case err := <-authResult:
				require.ErrorIs(t, err, tc.wantError)
				require.Equal(t, tc.wantPamErrorMessages, gh.pamErrorMessages,
					"PAM Error messages do not match")
				require.Equal(t, tc.wantPamInfoMessages, gh.pamInfoMessages,
					"PAM Info messages do not match")

				if err != nil {
					return
				}

				user, err := gh.tx.GetItem(pam.User)
				require.NoError(t, err)
				require.Equal(t, tc.pamUser, user)
			}
		})
	}
}

func buildPAMLibrary(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("go", "build", "-C", "..",
		"-buildmode=c-shared", "-gcflags=-dwarflocationlists=true")
	if testutils.CoverDir() != "" {
		// -cover is a "positional flag", so it needs to come right after the "build" command.
		cmd.Args = append(cmd.Args, "-cover")
	}
	if pam_test.IsAddressSanitizerActive() {
		cmd.Args = append(cmd.Args, "-asan")
	}

	libPath := filepath.Join(t.TempDir(), "libpam_authd.so")
	t.Logf("Compiling PAM library at %s", libPath)

	cmd.Args = append(cmd.Args, "-tags=pam_debug,pam_gdm_debug", "-o", libPath)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, out)

	t.Cleanup(func() { os.Remove(libPath) })

	return libPath
}

func createServiceFile(t *testing.T, name string, libPath string, args []string, fallback string) string {
	t.Helper()

	serviceFile := filepath.Join(t.TempDir(), name)
	t.Logf("Creating service file at %s", serviceFile)

	err := os.WriteFile(serviceFile,
		[]byte(fmt.Sprintf(`auth [success=done ignore=ignore default=die] %s %s
auth requisite pam_debug.so auth=%s`, libPath, strings.Join(args, " "), fallback)),
		0600)
	require.NoError(t, err)
	return serviceFile
}
