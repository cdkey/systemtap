#include <stdio.h>
#include <errno.h>
#include <string.h>


int
main ()
{
  FILE *infile;
  char *input_file = "No_such_file";
  infile = fopen (input_file, "r");
  if (infile == NULL) 
    printf ("tlserrno: %s: %s\n", strerror(errno), input_file);
}
