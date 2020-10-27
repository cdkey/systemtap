#include <stdio.h>

#if defined EXTERN_TLS
 __thread unsigned long tls1 = 1; 
 __thread unsigned long tls2 = 2;
#else
static __thread unsigned long tls1 = 1; 
static __thread unsigned long tls2 = 2;
#endif

void* increase_tls_worker ();


void*
increase_tls (void *arg)
{
  tls1 = tls1 + (unsigned long)(*((char*)arg) - '0');
  tls2 = tls2 + (unsigned long)(*((char*)arg) - '0');
#if defined EXTERN_TLS
  increase_tls_worker();
#endif
stp_probe:
  printf ("tls counter for %c: %d/%d\n", (char)*((char*)arg), tls1, tls2);
}
