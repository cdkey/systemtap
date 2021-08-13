/* -*- linux-c -*-
 *
 * RISC-V dwarf unwinder header file
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _STP_RISCV_UNWIND_H
#define _STP_RISCV_UNWIND_H

#include <linux/sched.h>
#include <asm/ptrace.h>

#define _stp_get_unaligned(ptr) (*(ptr))

#define UNW_PC(frame)        (frame)->regs.epc
#define UNW_SP(frame)        (frame)->regs.sp

#define STACK_LIMIT(ptr)     (((ptr) - 1) & ~(THREAD_SIZE - 1))

#define UNW_REGISTER_INFO \
	PTREGS_INFO(epc), \
	PTREGS_INFO(ra), \
	PTREGS_INFO(sp), \
	PTREGS_INFO(gp), \
	PTREGS_INFO(tp), \
	PTREGS_INFO(t0), \
	PTREGS_INFO(t1), \
	PTREGS_INFO(t2), \
	PTREGS_INFO(s0), \
	PTREGS_INFO(s1), \
	PTREGS_INFO(a0), \
	PTREGS_INFO(a1), \
	PTREGS_INFO(a2), \
	PTREGS_INFO(a3), \
	PTREGS_INFO(a4), \
	PTREGS_INFO(a5), \
	PTREGS_INFO(a6), \
	PTREGS_INFO(a7), \
	PTREGS_INFO(s2), \
	PTREGS_INFO(s3), \
	PTREGS_INFO(s4), \
	PTREGS_INFO(s5), \
	PTREGS_INFO(s6), \
	PTREGS_INFO(s7), \
	PTREGS_INFO(s8), \
	PTREGS_INFO(s9), \
	PTREGS_INFO(s10), \
	PTREGS_INFO(s11), \
	PTREGS_INFO(t3), \
	PTREGS_INFO(t4), \
	PTREGS_INFO(t5), \
	PTREGS_INFO(t6)

#define UNW_PC_IDX 0
#define UNW_SP_IDX 2

/* Use default rules. The stack pointer should be set from the CFA.
   And the instruction pointer should be set from the return address
   column (which normally is the return register (regs[31]). */

static inline void arch_unw_init_frame_info(struct unwind_frame_info *info,
                                            /*const*/ struct pt_regs *regs,
					    int sanitize)
{
	if (&info->regs == regs) { /* happens when unwinding kernel->user */
		info->call_frame = 1;
		return;
	}

	memset(info, 0, sizeof(*info));
	/* XXX handle sanitize??? */
	info->regs = *regs;
}

#endif /* _STP_RISCV_UNWIND_H */
