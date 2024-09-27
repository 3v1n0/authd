package testutils

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

var (
	isVerbose           bool
	isVerboseOnce       sync.Once
	isRace              bool
	isRaceOnce          sync.Once
	isAsan              bool
	isAsanOnce          sync.Once
	sleepMultiplier     float64
	sleepMultiplierOnce sync.Once
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

func haveBuildFlag(flag string) bool {
	b, ok := debug.ReadBuildInfo()
	if !ok {
		panic("could not read build info")
	}

	flag = "-" + flag
	for _, s := range b.Settings {
		if s.Key != flag {
			continue
		}
		value, err := strconv.ParseBool(s.Value)
		if err != nil {
			panic(err)
		}
		return value
	}

	return false
}

// IsAsan returns whether the tests are running with address sanitizer.
func IsAsan() bool {
	isAsanOnce.Do(func() { isAsan = haveBuildFlag("asan") })
	return isAsan
}

// IsRace returns whether the tests are running with thread sanitizer.
func IsRace() bool {
	isRaceOnce.Do(func() { isRace = haveBuildFlag("race") })
	return isRace
}

// TestNativeAuthenticate/Authenticate_user_and_reset_password_while_enforcing_policy

// SleepMultiplier returns the sleep multiplier for the tests.
func SleepMultiplier() float64 {
	sleepMultiplierOnce.Do(func() {
		// for _, arg := range os.Args {
		// 	value, ok := strings.CutPrefix(arg, "-test.pamsleepmultiplier=")
		// 	if !ok {
		// 		continue
		// 	}
		// 	var err error
		// 	sleepMultiplier, err = strconv.ParseFloat(value, 64)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// }
		sleepMultiplier = 1
		if v := os.Getenv("AUTHD_TESTS_SLEEP_MULTIPLIER"); v != "" {
			var err error
			sleepMultiplier, err = strconv.ParseFloat(v, 64)
			if err != nil {
				panic(err)
			}
		}

		if IsAsan() {
			sleepMultiplier *= 1.5
		}
		if IsRace() {
			sleepMultiplier *= 4
		}
	})

	return sleepMultiplier
}
