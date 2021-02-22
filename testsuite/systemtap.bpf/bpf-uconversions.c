long a = 3;

int foo(long *b) {
  *b++;
}

int main(void) {
  a++;
  foo(&a);
  return 0;
}
