#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>

#if defined EXTERN_TLS
__thread unsigned long tls = 99; 
#else
static __thread unsigned long tls = 99; 
#endif

void *increase_tls(void *arg);


int main()
{
  pthread_t *thread;
  pthread_barrier_t barrier;
  int thread_count = 2;

  pthread_barrier_init (&barrier, NULL, thread_count);
  char thread_name[] = 
    { '0', '1', '2', '3', '4', '5' };

  thread = alloca (sizeof (pthread_t) * (thread_count + 1));
  for (int i = 1; i <= thread_count; i++)
    pthread_create (&thread[i], NULL, & increase_tls, &thread_name[i]);
 
  for (int i = 1; i <= thread_count; i++)
    pthread_join (thread[i], NULL);
}
