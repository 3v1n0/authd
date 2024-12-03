package main_test

import (
	"fmt"
	"maps"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd"
	permissionstestutils "github.com/ubuntu/authd/internal/services/permissions/testutils"
	"github.com/ubuntu/authd/internal/testutils"
	"github.com/ubuntu/authd/pam/internal/pam_test"
)

const (
	vhsWidth       = "Width"
	vhsHeight      = "Height"
	vhsFontFamily  = "FontFamily"
	vhsFontSize    = "FontSize"
	vhsPadding     = "Padding"
	vhsMargin      = "Margin"
	vhsShell       = "Shell"
	vhsWaitTimeout = "WaitTimeout"
	vhsWaitPattern = "WaitPattern"

	vhsCommandVariable = "AUTHD_TEST_TAPE_COMMAND"

	vhsCommandFinalAuthWaitVariable         = "AUTHD_TEST_TAPE_COMMAND_AUTH_FINAL_WAIT"
	vhsCommandFinalChangeAuthokWaitVariable = "AUTHD_TEST_TAPE_COMMAND_PASSWD_FINAL_WAIT"

	authdSleepDefault                 = "AUTHD_SLEEP_DEFAULT"
	authdSleepLong                    = "AUTHD_SLEEP_LONG"
	authdSleepFinal                   = "AUTHD_SLEEP_FINAL"
	authdSleepExampleBrokerMfaWait    = "AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT"
	authdSleepExampleBrokerQrcodeWait = "AUTHD_SLEEP_EXAMPLE_BROKER_QRCODE_WAIT"
	authdSleepQrCodeReselection       = "AUTHD_SLEEP_QRCODE_RESELECTION_WAIT"
)

type tapeSetting struct {
	Key   string
	Value any
}

type tapeData struct {
	Name      string
	Command   string
	Outputs   []string
	Settings  map[string]any
	Env       map[string]string
	Variables map[string]string
}

type vhsTestType int

const (
	vhsTestTypeCLI = iota
	vhsTestTypeNative
	vhsTestTypeSSH
)

func (tt vhsTestType) tapesPath(t *testing.T) string {
	t.Helper()

	switch tt {
	case vhsTestTypeCLI:
		return "cli"
	case vhsTestTypeNative:
		return "native"
	case vhsTestTypeSSH:
		return "ssh"
	default:
		t.Errorf("Unknown test type %d", tt)
		return ""
	}
}

var (
	defaultSleepValues = map[string]time.Duration{
		authdSleepDefault: 100 * time.Millisecond,
		authdSleepFinal:   60 * time.Millisecond,
		authdSleepLong:    1 * time.Second,
		// Keep these in sync with example broker default wait times
		authdSleepExampleBrokerMfaWait:    4 * time.Second,
		authdSleepExampleBrokerQrcodeWait: 4 * time.Second,
		// Keep this bigger or equal of qrcodemodel's reselectionWaitTime
		authdSleepQrCodeReselection: 400 * time.Millisecond,
	}

	vhsSleepRegex = regexp.MustCompile(
		`(?m)\$\{?(AUTHD_SLEEP_[A-Z_]+)\}?(\s?([*/]+)\s?([\d.]+))?(.*)$`)
	vhsEmptyLinesRegex = regexp.MustCompile(`(?m)((^\n^\n)+(^\n)?|^\n)(^─+$)`)

	// vhsWaitSuffix adds support for Wait+Suffix /Pattern/ command.
	vhsWaitSuffix = regexp.MustCompile(`\bWait\+Suffix(@\S+)?[\t ]+(/(.*)/|(.*))`)
	// vhsWaitPromptRegex adds support for Wait+Prompt /Pattern/ command.
	vhsWaitPromptRegex = regexp.MustCompile(`\bWait\+Prompt(@\S+)?[\t ]+(/(.*)/|(.*))`)
	// vhsWaitNth adds support for Wait+Nth(X) /Pattern/ command, where X is the
	// number of values of the same content we want to match.
	vhsWaitNth = regexp.MustCompile(`\bWait\+Nth\((\d+)\)(@\S+)?[\t ]+(/(.*)/|(.*))`)
)

func newTapeData(tapeName string, settings ...tapeSetting) tapeData {
	m := map[string]any{
		vhsWidth:  800,
		vhsHeight: 500,
		// TODO: Ideally, we should use Ubuntu Mono. However, the github runner is still on Jammy, which does not have it.
		// We should update this to use Ubuntu Mono once the runner is updated.
		vhsFontFamily:  "Monospace",
		vhsFontSize:    13,
		vhsPadding:     0,
		vhsMargin:      0,
		vhsShell:       "bash",
		vhsWaitTimeout: 10 * time.Second,
	}
	for _, s := range settings {
		m[s.Key] = s.Value
	}
	return tapeData{
		Name: tapeName,
		Outputs: []string{
			tapeName + ".txt",
			// If we don't specify a .gif output, it will still create a default out.gif file.
			tapeName + ".gif",
		},
		Settings: m,
		Env:      make(map[string]string),
	}
}

type clientOptions struct {
	PamUser        string
	PamEnv         []string
	PamServiceName string
	Term           string
	SessionType    string
}

func (td *tapeData) AddClientOptions(t *testing.T, opts clientOptions) {
	t.Helper()

	logFile := prepareFileLogging(t, "authd-pam-test-client.log")
	td.Env[pam_test.RunnerEnvLogFile] = logFile
	td.Env[pam_test.RunnerEnvTestName] = t.Name()

	if opts.PamUser != "" {
		td.Env[pam_test.RunnerEnvUser] = opts.PamUser
	}
	if opts.PamEnv != nil {
		td.Env[pam_test.RunnerEnvEnvs] = strings.Join(opts.PamEnv, ";")
	}
	if opts.PamServiceName != "" {
		td.Env[pam_test.RunnerEnvService] = opts.PamServiceName
	}
	if opts.Term != "" {
		td.Env["AUTHD_PAM_CLI_TERM"] = opts.Term
	}
	if opts.SessionType != "" {
		td.Env["XDG_SESSION_TYPE"] = opts.SessionType
	}
}

func (td tapeData) RunVhs(t *testing.T, testType vhsTestType, outDir string, cliEnv []string) {
	t.Helper()

	cmd := exec.Command("env", "vhs")
	cmd.Env = append(testutils.AppendCovEnv(cmd.Env), cliEnv...)
	cmd.Dir = outDir

	// If vhs is installed with "go install", we need to add GOPATH to PATH.
	cmd.Env = append(cmd.Env, prependBinToPath(t))

	u, err := user.Current()
	require.NoError(t, err, "Setup: getting current user")
	if u.Name == "root" || os.Getenv("SCHROOT_CHROOT_NAME") != "" {
		cmd.Env = append(cmd.Env, "VHS_NO_SANDBOX=1")
	}

	// Move some of the environment specific-variables from the tape to the launched process
	if e, ok := td.Env[pam_test.RunnerEnvLogFile]; ok {
		delete(td.Env, pam_test.RunnerEnvLogFile)
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", pam_test.RunnerEnvLogFile, e))
	}

	cmd.Args = append(cmd.Args, td.PrepareTape(t, testType, outDir))
	out, err := cmd.CombinedOutput()

	isSSHError := func(processOut []byte) bool {
		const sshConnectionResetByPeer = "Connection reset by peer"
		const sshConnectionClosed = "Connection closed by"
		output := string(processOut)
		if strings.Contains(output, sshConnectionResetByPeer) {
			return true
		}
		return strings.Contains(output, sshConnectionClosed)
	}
	if err != nil && testType == vhsTestTypeSSH && isSSHError(out) {
		t.Logf("SSH Connection failed on tape %q: %v: %s", td.Name, err, out)
		// Let's repeat first, if it fails again, let's just skip the test.
		//nolint:gosec // G204 it's a test and we explicitly set the parameters before.
		newCmd := exec.Command(cmd.Args[0], cmd.Args[1:]...)
		newCmd.Dir = cmd.Dir
		newCmd.Env = slices.Clone(cmd.Env)
		out, err = newCmd.CombinedOutput()
		if err != nil && isSSHError(out) {
			t.Skipf("SSH Connection failed on tape %q again, it's not an authd issue, ignoring it!\n%s\n",
				td.Name, out)
		}
	}
	require.NoError(t, err, "Failed to run tape %q: %v: %s", td.Name, err, out)
}

func (td tapeData) String() string {
	var str string
	for _, o := range td.Outputs {
		str += fmt.Sprintf("Output %q\n", o)
	}
	for s, v := range td.Settings {
		switch vv := v.(type) {
		case time.Duration:
			v = fmt.Sprintf("%dms", sleepDuration(vv).Milliseconds())
		case string:
			if s == vhsWaitPattern {
				// VHS wait pattern can be a regex, so don't quote it by default.
				break
			}
			v = fmt.Sprintf("%q", vv)
		}
		str += fmt.Sprintf(`Set %s %v`+"\n", s, v)
	}
	for s, v := range td.Env {
		str += fmt.Sprintf(`Env %s %q`+"\n", s, v)
	}
	return str
}

func (td tapeData) Output() string {
	var txt string
	for _, o := range td.Outputs {
		if strings.HasSuffix(o, ".txt") {
			txt = o
		}
	}
	return txt
}

func (td tapeData) ExpectedOutput(t *testing.T, outputDir string) string {
	t.Helper()

	outPath := filepath.Join(outputDir, td.Output())
	out, err := os.ReadFile(outPath)
	require.NoError(t, err, "Could not read output file of tape %q (%s)", td.Name, outPath)
	got := string(out)

	if testutils.IsRace() && strings.Contains(got, "WARNING: DATA RACE") &&
		strings.Contains(got, "bubbles/cursor.(*Model).BlinkCmd.func1") {
		// FIXME: This is a well known race of bubble tea:
		// https://github.com/charmbracelet/bubbletea/issues/909
		// We can't do much here, as the workaround will likely affect the
		// GUI behavior, but we ignore this since it's definitely not our bug.
		t.Skip("This is a very well known bubble tea bug (#909), ignoring it")
		if testutils.IsVerbose() {
			t.Logf("Ignored bubbletea race:\n%s", got)
		} else {
			fmt.Fprintf(os.Stderr, "Ignored bubbletea race:\n%s", got)
		}
	}

	// We need to format the output a little bit, since the txt file can have some noise at the beginning.
	command := "> " + td.Command
	maxCommandLen := 0
	splitTmp := strings.Split(got, "\n")
	for _, str := range splitTmp {
		maxCommandLen = max(maxCommandLen, utf8.RuneCountInString(str))
	}
	if len(command) > maxCommandLen {
		command = command[:maxCommandLen]
	}
	for i, str := range splitTmp {
		if strings.Contains(str, command) {
			got = strings.Join(splitTmp[i:], "\n")
			break
		}
	}

	got = permissionstestutils.IdempotentPermissionError(got)

	// Drop all the empty lines before each page separator, to remove the clutter.
	got = vhsEmptyLinesRegex.ReplaceAllString(got, "$4")

	// Save the sanitized result on cleanup
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		baseName, _ := strings.CutSuffix(td.Output(), ".txt")
		tempOutput := filepath.Join(t.TempDir(), fmt.Sprintf("%s_sanitized.txt", baseName))
		require.NoError(t, os.WriteFile(tempOutput, []byte(got), 0600),
			"TearDown: Saving sanitized output file %q", tempOutput)
		saveArtifactsForDebug(t, []string{tempOutput})
	})

	return got
}

func (td tapeData) PrepareTape(t *testing.T, testType vhsTestType, outputPath string) string {
	t.Helper()

	currentDir, err := os.Getwd()
	require.NoError(t, err, "Setup: Could not get current directory for the tests")

	tape, err := os.ReadFile(filepath.Join(
		currentDir, "testdata", "tapes", testType.tapesPath(t), td.Name+".tape"))
	require.NoError(t, err, "Setup: read tape file %s", td.Name)

	tapeString := evaluateTapeVariables(t, string(tape), td, testType)
	tape = []byte(strings.Join([]string{
		td.String(),
		tapeString,
		fmt.Sprintf("Sleep %dms",
			sleepDuration(defaultSleepValues[authdSleepFinal]).Milliseconds()),
	}, "\n"))

	tapePath := filepath.Join(outputPath, td.Name)
	err = os.WriteFile(tapePath, tape, 0600)
	require.NoError(t, err, "Setup: write tape file")

	artifacts := []string{tapePath}
	for _, o := range td.Outputs {
		artifacts = append(artifacts, filepath.Join(outputPath, o))
	}
	saveArtifactsForDebugOnCleanup(t, artifacts)

	return tapePath
}

func evaluateTapeVariables(t *testing.T, tapeString string, td tapeData, testType vhsTestType) string {
	t.Helper()

	for _, m := range vhsSleepRegex.FindAllStringSubmatch(tapeString, -1) {
		fullMatch, sleepKind, op, arg, rest := m[0], m[1], m[3], m[4], m[5]
		sleep, ok := defaultSleepValues[sleepKind]
		require.True(t, ok, "Setup: unknown sleep kind: %q", sleepKind)

		// We don't need to support math that is complex enough to use proper parsers as go.ast
		if arg != "" {
			parsedArg, err := strconv.ParseFloat(arg, 32)
			require.NoError(t, err, "Setup: Cannot parse expression %q: %q is not a float", fullMatch, arg)

			switch op {
			case "*":
				sleep = time.Duration(math.Round(float64(sleep) * parsedArg))
			case "/":
				require.NotZero(t, parsedArg, "Setup: Division by zero")
				sleep = time.Duration(math.Round(float64(sleep) / parsedArg))
			default:
				require.Empty(t, op, "Setup: Unhandled operator %q", op)
			}
		}

		replaceRegex := regexp.MustCompile(fmt.Sprintf(`(?m)%s$`, regexp.QuoteMeta(fullMatch)))
		tapeString = replaceRegex.ReplaceAllString(tapeString,
			fmt.Sprintf("%dms%s", sleepDuration(sleep).Milliseconds(), rest))
	}

	if td.Command == "" {
		require.NotContains(t, tapeString, fmt.Sprintf("${%s}", vhsCommandVariable),
			"Setup: Tape contains %q but it's not defined", vhsCommandVariable)
	}

	variables := td.Variables
	if td.Command != "" {
		if variables != nil {
			variables = maps.Clone(variables)
		}
		if variables == nil {
			variables = make(map[string]string)
		}
		variables[vhsCommandVariable] = td.Command
	}

	for k, v := range variables {
		variable := fmt.Sprintf("${%s}", k)
		require.Contains(t, tapeString, variable,
			"Setup: Tape does not contain %q", variable)
		tapeString = strings.ReplaceAll(tapeString, variable, v)
	}

	tapeString = strings.ReplaceAll(tapeString,
		fmt.Sprintf("${%s}", vhsCommandFinalAuthWaitVariable),
		finalWaitCommands(testType, authd.SessionMode_AUTH))
	tapeString = strings.ReplaceAll(tapeString,
		fmt.Sprintf("${%s}", vhsCommandFinalChangeAuthokWaitVariable),
		finalWaitCommands(testType, authd.SessionMode_PASSWD))

	tapeString = vhsWaitPromptRegex.ReplaceAllString(tapeString,
		`Wait+Suffix$1 /$3$4:\n>/`)
	tapeString = vhsWaitSuffix.ReplaceAllString(tapeString,
		`Wait+Screen$1 /$3$4[\n]*$$/`)
	tapeString = vhsWaitNth.ReplaceAllString(tapeString,
		`Wait+Screen$2 /($4$5(.|\n)+){$1}/`)

	return tapeString
}

func finalWaitCommands(testType vhsTestType, sessionMode authd.SessionMode) string {
	if testType != vhsTestTypeCLI {
		return "Wait"
	}

	firstResult := pam_test.RunnerResultActionAuthenticate
	if sessionMode == authd.SessionMode_PASSWD {
		firstResult = pam_test.RunnerResultActionChangeAuthTok
	}

	return fmt.Sprintf(`Wait+Screen /%s[^\n]*/
Wait+Screen /%s[^\n]*/
Wait`,
		regexp.QuoteMeta(firstResult.String()),
		regexp.QuoteMeta(pam_test.RunnerResultActionAcctMgmt.String()),
	)
}

func requireRunnerResultForUser(t *testing.T, sessionMode authd.SessionMode, user, goldenContent string) {
	t.Helper()

	// Only check the last 50 lines of the golden file, because that's where
	// the result is printed, while printing the full output on failure is too much.
	goldenLines := strings.Split(goldenContent, "\n")
	goldenContent = strings.Join(goldenLines[max(0, len(goldenLines)-50):], "\n")

	require.Contains(t, goldenContent, pam_test.RunnerAction(sessionMode).Result().Message(user),
		"Golden file does not include required value, consider increasing the terminal size:\n%s",
		goldenContent)
	require.Contains(t, goldenContent, pam_test.RunnerResultActionAcctMgmt.Message(user),
		"Golden file does not include required value, consider increasing the terminal size:\n%s",
		goldenContent)
}

func requireRunnerResult(t *testing.T, sessionMode authd.SessionMode, goldenContent string) {
	t.Helper()

	requireRunnerResultForUser(t, sessionMode, "", goldenContent)
}
