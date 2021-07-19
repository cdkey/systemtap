/*
 * Is this a kernel prior to the following kernel commit:
 *
 * commit	2f064a59a11ff9bc22e52e9678bc601404c7cb34
 * Author:	Peter Zijlstra <peterz@infradead.org>
 * Date:	2021-06-11 10:28:17 +0200
 *
 * sched: Change task_struct::state
 * Change the type and name of task_struct::state. Drop the volatile and
 * shrink it to an 'unsigned int'. Rename it in order to find all uses
 * such that we can use READ_ONCE/WRITE_ONCE as appropriate.
 */

#include <linux/sched.h>

unsigned int bar (struct task_struct *foo) { 
  return (foo->state = 0); 
}
