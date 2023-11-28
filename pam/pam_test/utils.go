// Package pam_test includes test tools for the PAM module
package pam_test

/*
#include <stdlib.h>

#ifdef __SANITIZE_ADDRESS__
#include <sanitizer/lsan_interface.h>
#endif

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
	"unsafe"

	"github.com/msteinert/pam"
)

// MaybeDoLeakCheck triggers the garbage collector and if the go program is
// compiled with -asan flag, do a memory leak check.
// This is meant to be used as a test Cleanup function, to force Go detecting
// if allocated resources have been released, e.g. using
// t.Cleanup(pam_test.MaybeDoLeakCheck)
func MaybeDoLeakCheck() {
	runtime.GC()
	time.Sleep(time.Millisecond * 10)
	C.maybe_do_leak_check()
}

func allocateCBytes(bytes []byte) pam.BinaryPointer {
	if bytes == nil {
		return nil
	}
	return pam.BinaryPointer(C.CBytes(bytes))
}

func cBytesToBytes(ptr pam.BinaryPointer, size int) []byte {
	if ptr == nil {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(size))
}

func releaseCBytesPointer(ptr pam.BinaryPointer) {
	C.free(unsafe.Pointer(ptr))
}
