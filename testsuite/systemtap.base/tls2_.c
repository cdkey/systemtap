#include <stdio.h>

extern __thread unsigned long tls1;
extern __thread unsigned long tls2;
extern __thread unsigned long tls;

void*
increase_tls_worker ()
{
 stp_probe:
  printf ("tls: %d/%d/%d\n", tls, tls1, tls2);
}
