#include <linux/tracepoint.h>

void baz (struct task_struct *parent, struct task_struct *child) {
	(void) parent;
	(void) child;
}

/* Until 2.6.35 (commit 38516ab59fbc5b), register_trace_* took one argument.
   Until 5.7.0 (commit a2806ef77ff9a9), this could be checked by checking
   for the absence of DECLARE_TRACE_NOARGS. Now _NOARGS variant is removed. */
void bar (void) {
	register_trace_sched_process_fork(baz, NULL);
}
