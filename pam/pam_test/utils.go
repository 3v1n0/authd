// Package pam_test includes Test tools for the PAM module
package pam_test

/*
void __lsan_do_leak_check (void) __attribute__ ((weak));

static inline void
maybe_do_leak_check (void)
{
  if (__lsan_do_leak_check != NULL)
    __lsan_do_leak_check ();
}
*/
import "C"

import (
	"os"
	"runtime"
	"time"
)

// MaybeDoLeakCheck triggers the garbage collector and if the go program is
// compiled with -asan flag, do a memory leak check.
// This is meant to be used as a test Cleanup function, to force Go detecting
// if allocated resources have been released, e.g. using
// t.Cleanup(pam_test.MaybeDoLeakCheck)
func MaybeDoLeakCheck() {
	if os.Getenv("AUTHD_PAM_SKIP_LEAK_CHECK") != "" {
		return
	}
	runtime.GC()
	time.Sleep(time.Millisecond * 10)
	C.maybe_do_leak_check()
}
