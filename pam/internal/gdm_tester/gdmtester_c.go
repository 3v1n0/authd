package main

/*
#include <stdlib.h>
#include <stdbool.h>

#cgo LDFLAGS: -ldl -lpam

#ifdef __SANITIZE_ADDRESS__
#include <sanitizer/lsan_interface.h>
#endif

static inline bool
have_asan_support (void)
{
#ifdef __SANITIZE_ADDRESS__
	return true;
#else
	return false;
#endif
}

static inline void
maybe_do_leak_check (void)
{
#ifdef __SANITIZE_ADDRESS__
	__lsan_do_leak_check();
#endif
}
*/
import "C"

import (
	"runtime"
	"time"
)

func maybeDoLeakCheck() {
	runtime.GC()
	time.Sleep(time.Millisecond * 10)
	C.maybe_do_leak_check()
}

// IsAddressSanitizerActive can be used to detect if address sanitizer is active.
func isAddressSanitizerActive() bool {
	return bool(C.have_asan_support())
}
