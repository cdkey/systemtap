#ifdef SHARED

enum countries {canada,usa,mexico};
enum countries country = mexico;

void
test_enum (int arg1, int arg2)
{
}

#else
void test_enum (int arg1, int arg2);

enum caps {A='A', B='B', C='C'};
enum caps cap = C;

enum sixteen_powers {sixteen_power_0=0,sixteen_power_1=16,sixteen_power_2=256,
  sixteen_power_3=4096,sixteen_power_4=65536, sixteen_power_5=1048576,
  sixteen_power_6=16777216,sixteen_power_7=268435456,sixteen_power_8=4294967296
  };
enum sixteen_powers sixteen_power = sixteen_power_8;

int
main ()
{
  enum enumdigits {one=1,two=2,three=3};

  typedef enum {a='a',b='b',c='c'} letters;
  letters letter = a;

  typedef enum {ten=10,twenty=20,thirty=30} linears;
  linears linear = twenty;

  typedef enum { at='@',sharp='#' } symbols;
  symbols symbol = at;

  struct 
  {
    enum ordinals {first=1,second=2,third=3};
    enum ordinals ordinal = first;
  } astruct;

  {
    enum ordinals {first=1,second=2,third=3,fourth=4};
    enum colors {orange=1,green=2,yellow=3};
  END_BLOCK:
    test_enum (orange, fourth);
  }
      
 RETURN:
  test_enum (astruct.first, astruct.second);
}

#endif
