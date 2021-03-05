//#include <stdio.h>

long a = 3;

void foo(long *b) {
  (*b)++;
}

int main(void) {
  //printf("initial a: %d\n", a);
  a++;
  foo(&a);
  //printf("final a: %d\n", a);
  return 0;
}
