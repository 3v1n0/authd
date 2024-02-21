package main_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

func testGdmModule(t *testing.T, libPath string, args []string) {
	t.Helper()

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

	// libpam won't ever return a pam.ErrIgnore, so we use a fallback error.
	// We use incomplete here, but it could be any.
	const ignoreError = pam.ErrIncomplete
	const pamDebugIgnoreError = "incomplete"

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
		wantAcctMgmtErr      error
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
		"Authenticates user2 with multiple retries": {
			pamUser:     "user2",
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
			wantError:       pam.ErrCredUnavail,
			wantAcctMgmtErr: ignoreError,
		},
		"Error on missing user": {
			pamUser: "",
			wantPamErrorMessages: []string{
				"can't select broker: rpc error: code = InvalidArgument desc = can't start authentication transaction: rpc error: code = InvalidArgument desc = no user name provided",
			},
			wantError:       pam.ErrSystem,
			wantAcctMgmtErr: ignoreError,
		},
		"Error on no supported layouts": {
			pamUser:          "user-bar",
			supportedLayouts: []*authd.UILayout{},
			wantPamErrorMessages: []string{
				"UI does not support any layouts",
			},
			wantError:       pam.ErrCredUnavail,
			wantAcctMgmtErr: ignoreError,
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
			wantError:       pam.ErrSystem,
			wantAcctMgmtErr: ignoreError,
		},
		"Error (ignored) on local broker causes fallback error": {
			pamUser:    "user-foo",
			brokerName: localBrokerName,
			wantPamInfoMessages: []string{
				"auth=" + pamDebugIgnoreError,
			},
			wantError:       ignoreError,
			wantAcctMgmtErr: pam.ErrAbort,
		},
		"Error on authenticating user2 with too many retries": {
			pamUser: "user2",
			authModeIDs: []string{
				passwordAuthID,
				passwordAuthID,
				passwordAuthID,
				passwordAuthID,
				passwordAuthID,
				passwordAuthID,
			},
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
			wantError:       pam.ErrAuth,
			wantAcctMgmtErr: ignoreError,
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
			wantError:       pam.ErrAuth,
			wantAcctMgmtErr: ignoreError,
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
			wantError:       pam.ErrAuth,
			wantAcctMgmtErr: ignoreError,
		},
	}
	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Cleanup(pam_test.MaybeDoLeakCheck)
			t.Parallel()

			// We run a daemon for each test, because here we don't want to
			// make assumptions whether the state of the broker and each test
			// should run in parallel and work the same way in any order is ran.
			ctx, cancel := context.WithCancel(context.Background())
			socketPath, stopped := testutils.RunDaemon(ctx, t, daemonPath,
				testutils.WithEnvironment(grouptests.GPasswdMockEnv(t, gpasswdOutput, groupsFile)...),
			)
			t.Cleanup(func() {
				cancel()
				<-stopped
			})
			serviceFile := createServiceFile(t, "module-loader", libPath,
				append(slices.Clone(args), "socket="+socketPath), pamDebugIgnoreError)

			gh := newGdmTestModuleHandler(t, serviceFile, tc.pamUser)
			t.Cleanup(func() { require.NoError(t, gh.tx.End()) })
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

			var err error
			select {
			case <-time.After(10 * time.Second):
				t.Fatal("Authentication timed out!")
			case err = <-authResult:
			}

			require.ErrorIs(t, err, tc.wantError)
			require.Equal(t, tc.wantPamErrorMessages, gh.pamErrorMessages,
				"PAM Error messages do not match")
			require.Equal(t, tc.wantPamInfoMessages, gh.pamInfoMessages,
				"PAM Info messages do not match")

			require.ErrorIs(t, gh.tx.AcctMgmt(pam.Flags(0)), tc.wantAcctMgmtErr,
				"Account Management PAM Error messages do not match")

			if tc.wantError != nil {
				return
			}

			user, err := gh.tx.GetItem(pam.User)
			require.NoError(t, err)
			require.Equal(t, tc.pamUser, user)
		})
	}
}

func TestGdmModule(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	libPath := buildPAMModule(t)
	testGdmModule(t, libPath, nil)
}

func TestGdmModuleWithCWrapper(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	wrapperLibPath := buildPAMWrapperModule(t)
	libPath := buildPAMModule(t)
	testGdmModule(t, wrapperLibPath, []string{libPath})
}

func buildPAMModule(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("go", "build", "-C", "..",
		"-buildmode=c-shared", "-gcflags=-dwarflocationlists=true")
	cmd.Env = append(os.Environ(), `CGO_CFLAGS=-O0 -g3`)
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
	require.NoError(t, err, string(out))

	return libPath
}

func buildPAMWrapperModule(t *testing.T) string {
	t.Helper()

	compiler := os.Getenv("CC")
	if compiler == "" {
		compiler = "cc"
	}

	//nolint:gosec // G204 it's a test so we should allow using any compiler safely.
	cmd := exec.Command(compiler)
	soname := "pam_authd_loader"
	libPath := filepath.Join(t.TempDir(), soname+".so")

	require.NoError(t, os.MkdirAll(filepath.Dir(libPath), 0700))
	t.Logf("Compiling PAM Wrapper library at %s", libPath)
	cmd.Args = append(cmd.Args, []string{
		"-o", libPath,
		"../go-loader/module.c",
		"-g3",
		"-O0",
	}...)

	if modulesPath := os.Getenv("AUTHD_PAM_MODULES_PATH"); modulesPath != "" {
		cmd.Args = append(cmd.Args, os.Getenv("AUTHD_PAM_MODULES_PATH"))
	}

	if pam_test.IsAddressSanitizerActive() {
		cmd.Args = append(cmd.Args, "-fsanitize=address,undefined")
	}
	if cflags := os.Getenv("CFLAGS"); cflags != "" && os.Getenv("DEB_BUILD_ARCH") == "" {
		cmd.Args = append(cmd.Args, strings.Split(cflags, " ")...)
	}

	cmd.Args = append(cmd.Args, []string{
		"-Wl,--as-needed",
		"-Wl,--allow-shlib-undefined",
		"-shared",
		"-fPIC",
		"-Wl,--unresolved-symbols=report-all",
		"-Wl,-soname," + soname + "",
		"-lpam",
	}...)
	if ldflags := os.Getenv("LDFLAGS"); ldflags != "" && os.Getenv("DEB_BUILD_ARCH") == "" {
		cmd.Args = append(cmd.Args, strings.Split(ldflags, " ")...)
	}

	if testutils.CoverDir() != "" {
		cmd.Args = append(cmd.Args, "--coverage")
		cmd.Args = append(cmd.Args, "-fprofile-abs-path")

		t.Cleanup(func() {
			t.Log("Running gcov...")
			gcov := exec.Command("gcov")
			gcov.Args = append(gcov.Args,
				"-pb", "-o", filepath.Dir(libPath),
				soname+".so-module.gcno")
			gcov.Dir = testutils.CoverDir()
			out, err := gcov.CombinedOutput()
			require.NoError(t, err, string(out))
			t.Log(string(out))
		})
	}

	t.Logf("Running compiler command: %s %s", cmd.Path, strings.Join(cmd.Args[1:], " "))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	return libPath
}

func createServiceFile(t *testing.T, name string, libPath string, args []string, ignoreError string) string {
	t.Helper()

	serviceFile := filepath.Join(t.TempDir(), name)
	t.Logf("Creating service file at %s", serviceFile)

	err := os.WriteFile(serviceFile,
		[]byte(fmt.Sprintf(`auth [success=done ignore=ignore default=die] %[1]s %[2]s
auth requisite pam_debug.so auth=%[3]s
account [success=done ignore=ignore default=die] %[1]s %[2]s
account requisite pam_debug.so acct=%[3]s`, libPath, strings.Join(args, " "), ignoreError)),
		0600)
	require.NoError(t, err)
	return serviceFile
}
