package testutils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	goCoverDir     string
	goCoverDirOnce sync.Once
)

// fqdnToPath allows to return the fqdn path for this file relative to go.mod.
func fqdnToPath(t *testing.T, path string) string {
	t.Helper()

	srcPath, err := filepath.Abs(path)
	require.NoError(t, err, "Setup: can't calculate absolute path")

	d := srcPath
	for d != "/" {
		f, err := os.Open(filepath.Clean(filepath.Join(d, "go.mod")))
		if err != nil {
			d = filepath.Dir(d)
			continue
		}
		defer func() { assert.NoError(t, f.Close(), "Setup: can’t close go.mod") }()

		r := bufio.NewReader(f)
		l, err := r.ReadString('\n')
		require.NoError(t, err, "can't read go.mod first line")
		if !strings.HasPrefix(l, "module ") {
			t.Fatal(`Setup: failed to find "module" line in go.mod`)
		}

		prefix := strings.TrimSpace(strings.TrimPrefix(l, "module "))
		relpath := strings.TrimPrefix(srcPath, d)
		return filepath.Join(prefix, relpath)
	}

	t.Fatal("failed to find go.mod")
	return ""
}

// AppendCovEnv returns the env needed to enable coverage when running a go binary.
func AppendCovEnv(env []string) []string {
	if CoverDir() == "" {
		return env
	}
	return append(env, fmt.Sprintf("GOCOVERDIR=%s", CoverDir()))
}

// CoverDir parses the arguments to find the cover profile file.
func CoverDir() string {
	goCoverDirOnce.Do(func() {
		for _, arg := range os.Args {
			goCoverDir, ok := strings.CutPrefix(arg, "-test.gocoverdir=")
			if !ok {
				continue
			}

			_, err := os.Stat(goCoverDir)
			if err == nil {
				return
			}
			if !errors.Is(err, os.ErrNotExist) {
				panic(err)
			}
			err = os.MkdirAll(goCoverDir, 0700)
			if err != nil {
				panic(err)
			}
		}
	})
	return goCoverDir
}

// writeGoCoverageLine writes given line in go coverage format to w.
func writeGoCoverageLine(t *testing.T, w io.Writer, file string, lineNum, lineLength int, covered string) {
	t.Helper()

	_, err := w.Write([]byte(fmt.Sprintf("%s:%d.1,%d.%d 1 %s\n", file, lineNum, lineNum, lineLength, covered)))
	require.NoErrorf(t, err, "Teardown: can't write a write to golang compatible cover file : %v", err)
}
