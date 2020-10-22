#include <linux/atomic.h>

int foo(atomic_t *v)
{
	return atomic_fetch_add_unless(v, 1, 0);
}
