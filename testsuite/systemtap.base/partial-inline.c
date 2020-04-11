extern void abort (void);
volatile int v;
#define V1 v++; v++; v++; v++; v++; v++; v++; v++; v++; v++;
#define V2 V1 V1 V1 V1 V1 V1 V1 V1 V1 V1
static int
foo (int x)
{
  int a = 2 * x + 4;
  int b = 6;
  if (x < 30)
    {
      int c = 8;
      int d = 8 * x;
      return 6;
    }
  else
    {
      int e = 134;
      int f = 9 * x;
      V2
      return v + 17;
    }
}

int
main (void)
{
  if (foo (v) > 10000)
    abort ();
  foo (70);
  return 0;
}
