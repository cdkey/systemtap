#include <stdio.h>

static __thread unsigned long tls1 = 1; 
static __thread unsigned long tls2 = 2;

void*
increase_tls (void *arg)
{
  tls1 = tls1 + (unsigned long)(*((char*)arg) - '0');
  tls2 = tls2 + (unsigned long)(*((char*)arg) - '0');
  printf ("tls counter for %c: %d/%d\n", (char)*((char*)arg), tls1, tls2);
}
