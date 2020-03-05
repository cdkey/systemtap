#include <linux/kernel.h>
#include <linux/string.h>

int bar (void) {
  static char *fmt = "%s\n";
  trace_printk (fmt, "hello world");
  return 0;
}

