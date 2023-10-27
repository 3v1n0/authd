// Package utils provide some utility tools for the PAM module code
package utils

/*
#include "utils.h"
*/
import "C"

import (
	"runtime"
	"testing"
	"time"
)

// MaybeDoLeakCheck allows to perform leak check when compiling with `-asan`
func MaybeDoLeakCheck() {
	runtime.GC()
	time.Sleep(time.Millisecond * 25)
	C.maybe_do_leak_check()
}

// TestLeaks allows to perform leak check at test cleanup when compiling
// with `-asan`
func TestLeaks(t *testing.T) {
	t.Cleanup(MaybeDoLeakCheck)
}
