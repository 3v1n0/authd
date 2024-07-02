package testutils

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

var (
	isVerbose     bool
	isVerboseOnce sync.Once
	isRace        bool
	isRaceOnce    sync.Once
)

// IsVerbose returns whether the tests are running in verbose mode.
func IsVerbose() bool {
	isVerboseOnce.Do(func() {
		for _, arg := range os.Args {
			value, ok := strings.CutPrefix(arg, "-test.v=")
			if !ok {
				continue
			}
			isVerbose = value == "true"
		}
	})
	return isVerbose
}

// IsRace returns whether the tests are running in verbose mode.
func IsRace() bool {
	isRaceOnce.Do(func() {
		b, ok := debug.ReadBuildInfo()
		if !ok {
			panic("could not read build info")
		}

		for _, s := range b.Settings {
			if s.Key != "-race" {
				continue
			}
			var err error
			isRace, err = strconv.ParseBool(s.Value)
			if err != nil {
				panic(err)
			}
		}
	})
	return isRace
}
