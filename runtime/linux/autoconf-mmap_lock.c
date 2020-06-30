#include <linux/mm_types.h>
#include <linux/mmap_lock.h>

int foobar(struct mm_struct *mm) { 
        mmap_write_lock (mm);
        mmap_read_unlock (mm);
        return 0;
}
