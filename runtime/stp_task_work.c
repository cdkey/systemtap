#ifndef _STP_TASK_WORK_C
#define _STP_TASK_WORK_C

#include "linux/task_work_compatibility.h"

#if !defined(STAPCONF_TASK_WORK_ADD_EXPORTED)
// First typedef from the original decls, then #define as typecasted calls.
typedef typeof(&task_work_add) task_work_add_fn;
#define task_work_add (* (task_work_add_fn)kallsyms_task_work_add)
#endif
#if !defined(STAPCONF_TASK_WORK_CANCEL_EXPORTED)
typedef typeof(&task_work_cancel) task_work_cancel_fn;
#define task_work_cancel (* (task_work_cancel_fn)kallsyms_task_work_cancel)
#endif

/* To avoid a crash when a task_work callback gets called after the
 * module is unloaded, keep track of the number of current callbacks. */
static atomic_t stp_task_work_callbacks = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(stp_task_work_waitq);

/*
 * stp_task_work_init() should be called before any other
 * stp_task_work_* functions are called to do setup.
 */
static int
stp_task_work_init(void)
{
#if !defined(STAPCONF_TASK_WORK_ADD_EXPORTED)
	/* The task_work_add()/task_work_cancel() functions aren't
	 * exported. Look up those function addresses. */
        kallsyms_task_work_add = (void *)kallsyms_lookup_name("task_work_add");
        if (kallsyms_task_work_add == NULL) {
		_stp_error("Can't resolve task_work_add!");
		return -ENOENT;
        }
#endif
#if !defined(STAPCONF_TASK_WORK_CANCEL_EXPORTED)
        kallsyms_task_work_cancel = (void *)kallsyms_lookup_name("task_work_cancel");
        if (kallsyms_task_work_cancel == NULL) {
		_stp_error("Can't resolve task_work_cancel!");
		return -ENOENT;
        }
#endif
	return 0;
}

/*
 * stap_task_work_exit() should be called when no more
 * stp_task_work_* functions will be called (before module exit).
 *
 * This function makes sure that all the callbacks are finished before
 * letting the module unload.  If the module unloads before a callback
 * is called, the kernel will try to make a function call to an
 * invalid address.
 */
static void
stp_task_work_exit(void)
{
	wait_event(stp_task_work_waitq, !atomic_read(&stp_task_work_callbacks));
}

static void
stp_task_work_get(void)
{
	/*
	 * We use atomic_inc_return() here instead of atomic_inc() because
	 * atomic_inc_return() implies a full memory barrier and we need the
	 * updates to stp_task_work_callbacks to be ordered correctly, otherwise
	 * there could still be a task worker active after stp_task_work_exit()
	 * returns (assuming that no task workers are added *after*
	 * stp_task_work_exit() returns).
	 */
	atomic_inc_return(&stp_task_work_callbacks);
}

static void
stp_task_work_put(void)
{
	if (atomic_dec_and_test(&stp_task_work_callbacks))
		wake_up(&stp_task_work_waitq);
}

/*
 * Our task_work_add() wrapper that remembers that we've got a pending
 * callback.
 */
static int
stp_task_work_add(struct task_struct *task, struct task_work *twork)
{
	int rc;

	rc = task_work_add(task, twork, true);
	if (rc == 0)
		stp_task_work_get();
	return rc;
}

/*
 * Our task_work_cancel() wrapper that remembers that a callback has
 * been cancelled.
 */
static struct task_work *
stp_task_work_cancel(struct task_struct *task, task_work_func_t func)
{
	struct task_work *twork;

	twork = task_work_cancel(task, func);
	if (twork != NULL)
		stp_task_work_put();
	return twork;
}

/*
 * stp_task_work_func_done() should be called at the very end of a
 * task_work callback function so that we can keep up with callback
 * accounting.
 */
static void
stp_task_work_func_done(void)
{
	stp_task_work_put();
}


#endif /* _STP_TASK_WORK_C */
