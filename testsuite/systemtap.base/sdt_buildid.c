#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

void bar ();

#ifndef ONLY_MAIN
#include "sdt_buildid_.h"

void
bar ()
{
  printf("%s=%ld\n", "test_probe_0_semaphore", SDT_BUILDID_TEST_PROBE_0_ENABLED());
  if (SDT_BUILDID_TEST_PROBE_0_ENABLED())
    SDT_BUILDID_TEST_PROBE_0();
}
#endif

#ifndef NO_MAIN
int
main ()
{
  bar();
  return 0;
}
#endif
