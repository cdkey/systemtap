#include <linux/uaccess.h>

// XXX set_fs is an inline function, so we can't detect it with exportconf:
void __something(void)
{
  mm_segment_t oldfs = get_fs();
  set_fs(KERNEL_DS);
  set_fs(USER_DS);
  set_fs(oldfs);
}
