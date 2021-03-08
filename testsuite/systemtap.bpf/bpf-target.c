// XXX compile with -g without -O

//#include <stdio.h>

// for user_long.stp, user_atvar_error.stp
long a = 3;

// for user_long.stp
int i = -3; // 0x
short j = -2; // 0xfffe
char k = -1; // 0xff

void foo(long *b) {
  (*b)++;
}

void bar(int *b, short *c, char *d) {
  (void)b; (void)c; (void)d;
}

int main(void) {
  //printf("initial a: %d\n", a);
  a++;
  foo(&a);
  bar(&i,&j,&k);
  //printf("final a: %d\n", a);
  return 0;
}
