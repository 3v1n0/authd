package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/muesli/termenv"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd"
	"github.com/ubuntu/authd/internal/testutils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var daemonPath string

func TestIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	socketPath, stopped := testutils.RunDaemon(ctx, t, daemonPath)
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	// FIXME: wait for daemon started in a proper way...
	time.Sleep(time.Second * 2)
	conn, err := grpc.Dial("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	client := authd.NewPAMClient(conn)
	t.Cleanup(func() {
		err := conn.Close()
		require.NoError(t, err)
	})

	appState := model{
		pamh:                nil,
		client:              client,
		interactiveTerminal: true,
	}
	logrus.SetLevel(logrus.WarnLevel)

	tm := teatest.NewTestModel(t, &appState, teatest.WithInitialTermSize(80, 50))

	// Examples
	// https://github.com/charmbracelet/x/blob/main/exp/teatest/app_test.go
	// https://github.com/jdbann/forestry/blob/9a3a8e793c6f90b3b9f403c916153a480eec7a75/model/stack/model_test.go#L43
	runStep := func(name string, waitFor []byte) {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			teatest.WaitFor(t, io.TeeReader(tm.Output(), &out), func(bts []byte) bool {
				// fmt.Println(string(bts))
				return bytes.Contains(bts, waitFor)
			})

			readOutput, err := io.ReadAll(&out)
			require.NoError(t, err)
			teatest.RequireEqualOutput(t, readOutput)
		})
	}

	runStep("provider selection", []byte("Select your provider"))

	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	runStep("password auth", []byte("Gimme your password"))
	tm.Type("goodpass")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	out, err := io.ReadAll(tm.FinalOutput(t))
	require.NoError(t, err)
	teatest.RequireEqualOutput(t, out)

	tm.FinalModel(t)
	require.Equal(t, appState.exitMsg.String(), pamSuccess{}.String())

	tm.Send(tea.Quit())
}

func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.Ascii)
	execPath, daemonCleanup, err := testutils.BuildDaemon(true)
	if err != nil {
		log.Printf("Setup: Failed to build authd daemon: %v", err)
		os.Exit(1)
	}
	defer daemonCleanup()
	daemonPath = execPath

	m.Run()
}
