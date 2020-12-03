/* -*- linux-c -*- 
 * Print Functions
 * Copyright (C) 2007-2018 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STAPLINUX_PRINT_C_
#define _STAPLINUX_PRINT_C_


#include "stp_string.h"
#include "print.h"
#include "transport/transport.c"
#include "vsprintf.c"

/** @file print.c
 * Printing Functions.
 */

/** @addtogroup print Print Functions
 * The print buffer is for collecting output to send to the user daemon.
 * This is a per-cpu static buffer.  The buffer is sent when
 * _stp_print_flush() is called.
 *
 * The reason to do this is to allow multiple small prints to be combined then
 * timestamped and sent together to staprun. This is more efficient than sending
 * numerous small packets.
 *
 * This function is called automatically when the print buffer is full.
 * It MUST also be called at the end of every probe that prints something.
 * @{
 */

struct _stp_log {
	unsigned int len; /* Bytes used in the buffer */
	char buf[STP_BUFFER_SIZE];
	atomic_t reentrancy_lock;
};
#include "print_flush.c"

static struct _stp_log *_stp_log_pcpu;

/*
 * An atomic counter is used to synchronize every possible print buffer usage
 * with the _stp_print_cleanup() function. The cleanup function sets the counter
 * to INT_MAX after waiting for everything using the print buffer to finish. We
 * cannot use a lock primitive to implement this because lock_acquire() contains
 * tracepoints and print statements are used both inside and outside of probes.
 * If the lock were only used inside probes, the runtime context would protect
 * us from recursing into the lock_acquire() tracepoints and deadlocking. We
 * instead use _stp_print_ctr as if it were a read-write lock.
 */
static atomic_t _stp_print_ctr = ATOMIC_INIT(0);

/*
 * This disables IRQs to make per-CPU print buffer accesses atomic. There is a
 * reentrancy protection mechanism specifically for NMIs, since they can violate
 * our atomic guarantee. Reentrancy is otherwise allowed within code sections
 * that have the runtime context held (via _stp_runtime_entryfn_get_context()).
 */
static bool _stp_print_trylock_irqsave(unsigned long *flags)
{
	bool context_held = false;
	struct _stp_log *log;

	local_irq_save(*flags);
	if (!atomic_add_unless(&_stp_print_ctr, 1, INT_MAX))
		goto irq_restore;

	/*
	 * Check the per-CPU reentrancy lock for contention, unless the runtime
	 * context is already held, in which case we already have reentrancy
	 * protection. Otherwise, if the reentrancy lock is contented, that
	 * means we're either inside an NMI that fired while the current CPU was
	 * accessing the log buffer, or something is trying to nest calls to
	 * _stp_print_trylock_irqsave(). Our only choice is to reject the log
	 * access attempt in this case because log buffer corruption and panics
	 * could ensue if we're inside an NMI.
	 */
	if (_stp_runtime_context_trylock()) {
		struct context *c = _stp_runtime_get_context();
		context_held = c && atomic_read(&c->busy);
		_stp_runtime_context_unlock();
	}

	/* Fall back onto the reentrancy lock if the context isn't held */
	if (!context_held) {
		log = per_cpu_ptr(_stp_log_pcpu, raw_smp_processor_id());
		if (atomic_cmpxchg(&log->reentrancy_lock, 0, 1))
			goto print_unlock;
	}

	return true;

print_unlock:
	atomic_dec(&_stp_print_ctr);
irq_restore:
	local_irq_restore(*flags);
	return false;
}

static void _stp_print_unlock_irqrestore(unsigned long *flags)
{
	bool context_held = false;
	struct _stp_log *log;

	if (_stp_runtime_context_trylock()) {
		struct context *c = _stp_runtime_get_context();
		context_held = c && atomic_read(&c->busy);
		_stp_runtime_context_unlock();
	}

	if (!context_held) {
		log = per_cpu_ptr(_stp_log_pcpu, raw_smp_processor_id());
		atomic_set(&log->reentrancy_lock, 0);
	}

	atomic_dec(&_stp_print_ctr);
	local_irq_restore(*flags);
}

/* create percpu print and io buffers */
static int _stp_print_init (void)
{
	unsigned int cpu;

	_stp_log_pcpu = _stp_alloc_percpu(sizeof(*_stp_log_pcpu));
	if (!_stp_log_pcpu)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		struct _stp_log *log = per_cpu_ptr(_stp_log_pcpu, cpu);

		log->reentrancy_lock = (atomic_t)ATOMIC_INIT(0);
	}
	return 0;
}

static void _stp_print_cleanup (void)
{
	unsigned int cpu;

	/* Wait for the loggers to finish modifying the print buffers */
	while (atomic_cmpxchg(&_stp_print_ctr, 0, INT_MAX))
		cpu_relax();

	for_each_possible_cpu(cpu) {
		struct _stp_log *log = per_cpu_ptr(_stp_log_pcpu, cpu);

		/*
		 * Flush anything that could be left in the print buffer. It is
		 * safe to do this without any kind of synchronization mechanism
		 * because nothing is using this print buffer anymore.
		 */
		__stp_print_flush(log);
	}

	_stp_free_percpu(_stp_log_pcpu);
}

static inline void _stp_print_flush(void)
{
	struct _stp_log *log;
	unsigned long flags;

	if (!_stp_print_trylock_irqsave(&flags))
		return;

	log = per_cpu_ptr(_stp_log_pcpu, raw_smp_processor_id());
	__stp_print_flush(log);
	_stp_print_unlock_irqrestore(&flags);
}

#ifndef STP_MAXBINARYARGS
#define STP_MAXBINARYARGS 127
#endif


/** Reserves space in the output buffer for direct I/O. Must be called with
 * _stp_print_trylock_irqsave() held.
 */
static void * _stp_reserve_bytes (int numbytes)
{
	struct _stp_log *log;
	char *ret;

	if (unlikely(numbytes == 0 || numbytes > STP_BUFFER_SIZE))
		return NULL;

	log = per_cpu_ptr(_stp_log_pcpu, raw_smp_processor_id());
	if (unlikely(numbytes > (STP_BUFFER_SIZE - log->len)))
		__stp_print_flush(log);

	ret = &log->buf[log->len];
	log->len += numbytes;
	return ret;
}


static void _stp_unreserve_bytes (int numbytes)
{
	struct _stp_log *log;

	log = per_cpu_ptr(_stp_log_pcpu, raw_smp_processor_id());
	if (numbytes <= log->len)
		log->len -= numbytes;
}

/** Write 64-bit args directly into the output stream.
 * This function takes a variable number of 64-bit arguments
 * and writes them directly into the output stream.  Marginally faster
 * than doing the same in _stp_vsnprintf().
 * @sa _stp_vsnprintf()
 */
static void _stp_print_binary (int num, ...)
{
	unsigned long flags;
	va_list vargs;
	int i;
	int64_t *args;

	if (unlikely(num > STP_MAXBINARYARGS))
		num = STP_MAXBINARYARGS;

	if (!_stp_print_trylock_irqsave(&flags))
		return;

	args = _stp_reserve_bytes(num * sizeof(int64_t));
	if (args) {
		va_start(vargs, num);
		for (i = 0; i < num; i++)
			args[i] = va_arg(vargs, int64_t);
		va_end(vargs);
	}
	_stp_print_unlock_irqrestore(&flags);
}

/** Print into the print buffer.
 * Like C printf.
 *
 * @sa _stp_print_flush()
 */
static void _stp_printf (const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	_stp_vsnprintf(NULL, 0, fmt, args);
	va_end(args);
}

/** Write a string into the print buffer.
 * @param str A C string (char *)
 */

static void _stp_print (const char *str)
{
	struct _stp_log *log;
	unsigned long flags;

	if (!_stp_print_trylock_irqsave(&flags))
		return;

	log = per_cpu_ptr(_stp_log_pcpu, raw_smp_processor_id());
	while (1) {
		while (log->len < STP_BUFFER_SIZE && *str)
			log->buf[log->len++] = *str++;
		if (likely(!*str))
			break;
		__stp_print_flush(log);
	}
	_stp_print_unlock_irqrestore(&flags);
}

static void _stp_print_char (const char c)
{
	struct _stp_log *log;
	unsigned long flags;

	if (!_stp_print_trylock_irqsave(&flags))
		return;

	log = per_cpu_ptr(_stp_log_pcpu, raw_smp_processor_id());
	if (unlikely(log->len == STP_BUFFER_SIZE))
		__stp_print_flush(log);
	log->buf[log->len++] = c;
	_stp_print_unlock_irqrestore(&flags);
}

static void _stp_print_kernel_info(char *sname, char *vstr, int ctx, int num_probes)
{
	printk(KERN_DEBUG
               "%s (%s): systemtap: %s, base: %lx"
               ", memory: %ludata/%lutext/%uctx/%unet/%ualloc kb"
               ", probes: %d"
#if ! STP_PRIVILEGE_CONTAINS (STP_PRIVILEGE, STP_PR_STAPDEV)
               ", unpriv-uid: %d"
#endif
               "\n",
	       THIS_MODULE->name,
	       sname, /* name of source file */
	       vstr,  /* stap version */
#ifdef STAPCONF_MODULE_LAYOUT
	       (unsigned long) THIS_MODULE->core_layout.base,
	       (unsigned long) (THIS_MODULE->core_layout.size - THIS_MODULE->core_layout.text_size)/1024,
	       (unsigned long) (THIS_MODULE->core_layout.text_size)/1024,
#else
#ifndef STAPCONF_GRSECURITY
	       (unsigned long) THIS_MODULE->module_core,
	       (unsigned long) (THIS_MODULE->core_size - THIS_MODULE->core_text_size)/1024,
               (unsigned long) (THIS_MODULE->core_text_size)/1024,
#else
               (unsigned long) THIS_MODULE->module_core_rx,
	       (unsigned long) (THIS_MODULE->core_size_rw - THIS_MODULE->core_size_rx)/1024,
               (unsigned long) (THIS_MODULE->core_size_rx)/1024,
#endif
#endif
	       ctx/1024,
	       _stp_allocated_net_memory/1024,
	       (_stp_allocated_memory - _stp_allocated_net_memory - ctx)/1024,
               /* (un-double-counting net/ctx because they're also stp_alloc'd) */
               num_probes
#if ! STP_PRIVILEGE_CONTAINS (STP_PRIVILEGE, STP_PR_STAPDEV)
               , _stp_uid
#endif
                );
}

/** @} */
#endif /* _STAPLINUX_PRINT_C_ */
