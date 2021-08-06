#include <linux/fdtable.h>
#include <linux/file.h>

void
foo(void)
{
	struct file *filp = files_lookup_fd_raw(NULL, 0);
	(void) filp;
}
