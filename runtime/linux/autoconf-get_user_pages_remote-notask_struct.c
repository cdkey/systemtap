#include <linux/mm.h>

//
// The following kernel commit changed the get_user_pages_remote()
// function signature (again) for linux-5.9:
//
// commit 64019a2e467a288a16b65ab55ddcbf58c1b00187
// Author: Peter Xu <peterx@redhat.com>
// Date:   Tue Aug 11 18:39:01 2020 -0700
//
//     mm/gup: remove task_struct pointer for all gup code
//
//     After the cleanup of page fault accounting, gup does not need to pass
//     task_struct around any more.  Remove that parameter in the whole gup
//     stack.
//
// This changed the function signature from:
//
// long get_user_pages_remote(struct task_struct *tsk, struct mm_struct *mm,
//                             unsigned long start, unsigned long nr_pages,
//                             unsigned int gup_flags, struct page **pages,
//                             struct vm_area_struct **vmas, int *locked);
//
// to:
//
// long get_user_pages_remote(struct mm_struct *mm,
//                             unsigned long start, unsigned long nr_pages,
//                             unsigned int gup_flags, struct page **pages,
//                             struct vm_area_struct **vmas, int *locked);
//

long gupr_wrapper(struct mm_struct *mm,
		  unsigned long start, unsigned long nr_pages,
		  unsigned int gup_flags, struct page **pages,
		  struct vm_area_struct **vmas, int *locked)
{
    return get_user_pages_remote(mm, start, nr_pages, gup_flags,
				 pages, vmas, locked);
}
