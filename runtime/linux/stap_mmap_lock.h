#ifndef __STAP_MMAP_LOCK_H
#define __STAP_MMAP_LOCK_H

#ifdef STAPCONF_MMAP_LOCK
#include <linux/mmap_lock.h>
#else

/* for pre-5.8 kernels, emulate new api */

#define mmap_read_lock(mm) down_read(&mm->mmap_sem)
#define mmap_read_trylock(mm) down_read_trylock(&mm->mmap_sem)
#define mmap_read_unlock(mm) up_read(&mm->mmap_sem)

#endif
#endif
