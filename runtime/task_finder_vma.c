#ifndef TASK_FINDER_VMA_C
#define TASK_FINDER_VMA_C

#include <linux/file.h>
#include <linux/list.h>
#include <linux/jhash.h>

#include <linux/fs.h>
#include <linux/dcache.h>

#include "stp_helper_lock.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
static inline bool atomic_try_cmpxchg(atomic_t *v, int *old, int new)
{
	int r, o = *old;
	r = atomic_cmpxchg(v, o, new);
	if (unlikely(r != o))
		*old = r;
	return likely(r == o);
}
#endif

#ifndef STAPCONF_ATOMIC_FETCH_ADD_UNLESS
static inline int atomic_fetch_add_unless(atomic_t *v, int a, int u)
{
	int c = atomic_read(v);

	do {
		if (unlikely(c == u))
			break;
	} while (!atomic_try_cmpxchg(v, &c, c + a));

	return c;
}
#endif

#ifndef __STP_TF_HASH_BITS
#define __STP_TF_HASH_BITS 8
#endif
#define __STP_TF_TABLE_SIZE (1 << __STP_TF_HASH_BITS)

#ifndef TASK_FINDER_VMA_ENTRY_PATHLEN
#define TASK_FINDER_VMA_ENTRY_PATHLEN 64
#elif TASK_FINDER_VMA_ENTRY_PATHLEN < 8
#error "gimme a little more TASK_FINDER_VMA_ENTRY_PATHLEN"
#endif

struct __stp_tf_vma_entry {
	struct hlist_node hlist;

	struct rcu_head rcu;
	atomic_t refcount;
	struct task_struct *tsk;
	unsigned long vm_start;
	unsigned long vm_end;
	char path[TASK_FINDER_VMA_ENTRY_PATHLEN]; /* mmpath name, if known */

	// User data (possibly stp_module)
	void *user;
};

struct __stp_tf_vma_bucket {
	struct hlist_head head;
	stp_spinlock_t lock;
};

static struct __stp_tf_vma_bucket *__stp_tf_vma_map;

// __stp_tf_vma_new_entry(): Returns an newly allocated or NULL.
// Must only be called from user context.
// ... except, with inode-uprobes / task-finder2, it can be called from
// random tracepoints.  So we cannot sleep after all.
static struct __stp_tf_vma_entry *
__stp_tf_vma_new_entry(void)
{
	struct __stp_tf_vma_entry *entry;
	// Alloc using kmalloc rather than the stp variant. This way the RCU
	// callback freeing the entries will not depend on using a function
	// within this module to free the allocated memory (_stp_kfree), which
	// lets us omit a costly rcu_barrier operation upon module unload.
#ifdef CONFIG_UTRACE
	entry = kmalloc(sizeof(*entry), STP_ALLOC_SLEEP_FLAGS);
#else
	entry = kmalloc(sizeof(*entry), STP_ALLOC_FLAGS);
#endif
	return entry;
}

// __stp_tf_vma_put_entry(): Put a specified number of references on the entry.
static void
__stp_tf_vma_put_entry(struct __stp_tf_vma_bucket *bucket,
		       struct __stp_tf_vma_entry *entry, int count)
{
	unsigned long flags;
	int old;

	// We must atomically subtract only if the refcount is non-zero, as well
	// as check to see if the new refcount is zero, in which case we should
	// free the entry.
	old = atomic_fetch_add_unless(&entry->refcount, -count, 0);
	if (old - count)
		return;

	stp_spin_lock_irqsave(&bucket->lock, flags);
	hlist_del_rcu(&entry->hlist);
	stp_spin_unlock_irqrestore(&bucket->lock, flags);

	kfree_rcu(entry, rcu);
}

// stap_initialize_vma_map():  Initialize the free list.  Grabs the
// spinlock.  Should be called before any of the other stap_*_vma_map
// functions.  Since this is run before any other function is called,
// this doesn't need any locking.  Should be called from a user context
// since it can allocate memory.
static int
stap_initialize_vma_map(void)
{
	struct __stp_tf_vma_bucket *buckets;
	int i;

	buckets = _stp_kmalloc_gfp(sizeof(*buckets) * __STP_TF_TABLE_SIZE,
				   STP_ALLOC_SLEEP_FLAGS);
	if (!buckets)
		return -ENOMEM;

	for (i = 0; i < __STP_TF_TABLE_SIZE; i++) {
		struct __stp_tf_vma_bucket *bucket = &buckets[i];

		INIT_HLIST_HEAD(&bucket->head);
		stp_spin_lock_init(&bucket->lock);
	}

	__stp_tf_vma_map = buckets;
	return 0;
}

// stap_destroy_vma_map(): Unconditionally destroys vma entries.
// Nothing should be using it anymore.
static void
stap_destroy_vma_map(void)
{
	int i;

	if (!__stp_tf_vma_map)
		return;

	for (i = 0; i < __STP_TF_TABLE_SIZE; i++) {
		struct __stp_tf_vma_bucket *bucket = &__stp_tf_vma_map[i];
		struct __stp_tf_vma_entry *entry;
		struct hlist_node *node;

		rcu_read_lock();
		stap_hlist_for_each_entry_rcu(entry, node, &bucket->head, hlist)
			__stp_tf_vma_put_entry(bucket, entry, 1);
		rcu_read_unlock();
	}

	_stp_kfree(__stp_tf_vma_map);
}

// __stp_tf_vma_bucket(): Get the bucket that should contain the task.
static inline struct __stp_tf_vma_bucket *
__stp_tf_get_vma_bucket(struct task_struct *tsk)
{
	return &__stp_tf_vma_map[hash_ptr(tsk, __STP_TF_HASH_BITS)];
}

// Get vma entry if the vma is present in the vma map hash table satisfying the
// given condition.
#define __stp_tf_get_vma_map(bucket, tsk, acquire, condition)			\
({										\
	struct __stp_tf_vma_entry *entry, *found = NULL;			\
	struct hlist_node *node;						\
										\
	rcu_read_lock();							\
	stap_hlist_for_each_entry_rcu(entry, node, &bucket->head, hlist) {	\
		if (entry->tsk == tsk && (condition) &&				\
		    atomic_add_unless(&entry->refcount, acquire, 0)) {		\
			found = entry;						\
			break;							\
		}								\
	}									\
	rcu_read_unlock();							\
										\
	found;									\
})

// Add the vma info to the vma map hash table.
// Caller is responsible for name lifetime.
// Can allocate memory, so needs to be called
// only from user context.
static int
stap_add_vma_map_info(struct task_struct *tsk, unsigned long vm_start,
		      unsigned long vm_end, const char *path, void *user)
{
	struct __stp_tf_vma_bucket *bucket = __stp_tf_get_vma_bucket(tsk);
	struct __stp_tf_vma_entry *entry;
	struct hlist_node *node;
	unsigned long flags;
	size_t path_len;

	// Check if the entry already exists
	if (__stp_tf_get_vma_map(bucket, tsk, 0, entry->vm_start == vm_start))
		return -EEXIST;

	entry = __stp_tf_vma_new_entry();
	if (!entry)
		return -ENOMEM;

	// Fill in the new entry
	entry->refcount = (atomic_t)ATOMIC_INIT(1);
	entry->tsk = tsk;
	entry->vm_start = vm_start;
	entry->vm_end = vm_end;
	entry->user = user;

	path_len = strlen(path);
	if (path_len >= TASK_FINDER_VMA_ENTRY_PATHLEN - 3) {
		strlcpy(entry->path, "...", TASK_FINDER_VMA_ENTRY_PATHLEN);
		strlcpy(entry->path + 3,
			&path[path_len - TASK_FINDER_VMA_ENTRY_PATHLEN + 4],
			TASK_FINDER_VMA_ENTRY_PATHLEN - 3);
	} else {
		strlcpy(entry->path, path, TASK_FINDER_VMA_ENTRY_PATHLEN);
	}

	stp_spin_lock_irqsave(&bucket->lock, flags);
	hlist_add_head_rcu(&entry->hlist, &bucket->head);
	stp_spin_unlock_irqrestore(&bucket->lock, flags);
	return 0;
}

// Extend the vma info vm_end in the vma map hash table if there is already
// a vma_info which ends precisely where this new one starts for the given
// task. Returns zero on success, -ESRCH if no existing matching entry could
// be found.
static int
stap_extend_vma_map_info(struct task_struct *tsk, unsigned long vm_start,
			 unsigned long vm_end)
{
	struct __stp_tf_vma_bucket *bucket = __stp_tf_get_vma_bucket(tsk);
	struct __stp_tf_vma_entry *entry;

	entry = __stp_tf_get_vma_map(bucket, tsk, 1, entry->vm_end == vm_start);
	if (!entry)
		return -ESRCH;

	entry->vm_end = vm_end;
	__stp_tf_vma_put_entry(bucket, entry, 1);
	return 0;
}


// Remove the vma entry from the vma hash table.
// Returns -ESRCH if the entry isn't present.
static int
stap_remove_vma_map_info(struct task_struct *tsk, unsigned long vm_start)
{
	struct __stp_tf_vma_bucket *bucket = __stp_tf_get_vma_bucket(tsk);
	struct __stp_tf_vma_entry *entry;

	entry = __stp_tf_get_vma_map(bucket, tsk, 1, entry->vm_start == vm_start);
	if (!entry)
		return -ESRCH;

	// Put two references: one for the reference we just got,
	// and another to free the entry.
	__stp_tf_vma_put_entry(bucket, entry, 2);
	return 0;
}

// Finds vma info if the vma is present in the vma map hash table for
// a given task and address (between vm_start and vm_end).
// Returns -ESRCH if not present.
static int
stap_find_vma_map_info(struct task_struct *tsk, unsigned long addr,
		       unsigned long *vm_start, unsigned long *vm_end,
		       const char **path, void **user)
{
	struct __stp_tf_vma_bucket *bucket;
	struct __stp_tf_vma_entry *entry;

	if (!__stp_tf_vma_map)
		return -ESRCH;

	bucket = __stp_tf_get_vma_bucket(tsk);
	entry = __stp_tf_get_vma_map(bucket, tsk, 1, addr >= entry->vm_start &&
				     addr < entry->vm_end);
	if (!entry)
		return -ESRCH;

	if (vm_start)
		*vm_start = entry->vm_start;
	if (vm_end)
		*vm_end = entry->vm_end;
	if (path)
		*path = entry->path;
	if (user)
		*user = entry->user;

	__stp_tf_vma_put_entry(bucket, entry, 1);
	return 0;
}

// Finds vma info if the vma is present in the vma map hash table for
// a given task with the given user handle.
// Returns -ESRCH if not present.
static int
stap_find_vma_map_info_user(struct task_struct *tsk, void *user,
			    unsigned long *vm_start, unsigned long *vm_end,
			    const char **path)
{
	struct __stp_tf_vma_bucket *bucket;
	struct __stp_tf_vma_entry *entry;

	if (!__stp_tf_vma_map)
		return -ESRCH;

	bucket = __stp_tf_get_vma_bucket(tsk);
	entry = __stp_tf_get_vma_map(bucket, tsk, 1, entry->user == user);
	if (!entry)
		return -ESRCH;

	if (vm_start)
		*vm_start = entry->vm_start;
	if (vm_end)
		*vm_end = entry->vm_end;
	if (path)
		*path = entry->path;

	__stp_tf_vma_put_entry(bucket, entry, 1);
	return 0;
}

static int
stap_drop_vma_maps(struct task_struct *tsk)
{
	struct __stp_tf_vma_bucket *bucket = __stp_tf_get_vma_bucket(tsk);
	struct __stp_tf_vma_entry *entry;
	struct hlist_node *node;

	rcu_read_lock();
	stap_hlist_for_each_entry_rcu(entry, node, &bucket->head, hlist) {
		if (entry->tsk == tsk)
			__stp_tf_vma_put_entry(bucket, entry, 1);
	}
	rcu_read_unlock();
	return 0;
}

/*
 * stap_find_exe_file - acquire a reference to the mm's executable file
 *
 * Returns NULL if mm has no associated executable file.  User must
 * release file via fput().
 */
static struct file*
stap_find_exe_file(struct mm_struct* mm)
{
	// The following kernel commit changed the way the exported
	// get_mm_exe_file() works. This commit first appears in the
	// 4.1 kernel:
	//
	// commit 90f31d0ea88880f780574f3d0bb1a227c4c66ca3
	// Author: Konstantin Khlebnikov <khlebnikov@yandex-team.ru>
	// Date:   Thu Apr 16 12:47:56 2015 -0700
	// 
	//     mm: rcu-protected get_mm_exe_file()
	//     
	//     This patch removes mm->mmap_sem from mm->exe_file read side.
	//     Also it kills dup_mm_exe_file() and moves exe_file
	//     duplication into dup_mmap() where both mmap_sems are
	//     locked.
	//
	// So, for kernels >= 4.1, we'll use get_mm_exe_file(). For
	// kernels < 4.1 but with get_mm_exe_file() exported, we'll
	// still use our own code. The original get_mm_exe_file() can
	// sleep (since it calls down_read()), so we'll have to roll
	// our own.
#if defined(STAPCONF_DPATH_PATH) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
	return get_mm_exe_file(mm);
#else
	struct file *exe_file = NULL;

	// The down_read() function can sleep, so we'll call
	// down_read_trylock() instead, which can fail.  If it
	// fails, we'll just pretend this task didn't have a
	// exe file.
	if (mm && down_read_trylock(&mm->mmap_sem)) {

		// VM_EXECUTABLE was killed in kernel commit e9714acf,
		// but in kernels that new we can just use
		// mm->exe_file anyway. (PR14712)
#ifdef VM_EXECUTABLE
		struct vm_area_struct *vma;
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
				exe_file = vma->vm_file;
				break;
			}
		}
#else
		exe_file = mm->exe_file;
#endif
		if (exe_file)
			get_file(exe_file);
		up_read(&mm->mmap_sem);
	}
	return exe_file;
#endif
}

#endif /* TASK_FINDER_VMA_C */
