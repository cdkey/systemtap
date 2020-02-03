#include <linux/rcupdate.h>

// RHBZ1788662 rcu operations are rejected in idle-cpu contexts.
//
// We need to use rcu_is_watching() where available to skip probes in
// rcu-idle state.

struct context * _stp_runtime_get_context(void)
{
        if (! rcu_is_watching())
		return 0;
	//return rcu_dereference_sched(contexts[smp_processor_id()]);
	return (struct context *)0xea7bee75;
}
