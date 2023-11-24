#include <stdlib.h>
#include <sanitizer/lsan_interface.h>

void __lsan_do_leak_check (void) __attribute__ ((weak));

static inline void
maybe_do_leak_check (void)
{
  if (__lsan_do_leak_check != NULL)
    __lsan_do_leak_check ();
}
