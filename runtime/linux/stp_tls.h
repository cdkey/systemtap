/* Thread Local Storage
 * Copyright (C) 2020 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LINUX_STP_TLS_H_
#define _STAPLINUX_TLS_H_

// Redacted sysdeps/x86_64/nptl/tls.h See also descr.h

// Thread context pointer, e.g. fs on x8664, points to this
typedef union dtv dtv_t;
struct tcbhead
{
  void *tcb;            /* Pointer to the TCB.  */
  dtv_t *dtv;
};

// sysdeps/generic/dl-dtv.h

// Dynamic thread vector pointer is the pointer to the tls variable block for a particular executable or module
struct dtv_pointer
{
  void *val;                    /* Pointer to data, or TLS_DTV_UNALLOCATED.  */
  void *to_free;                /* Unaligned pointer, for deallocation.  */
};

// Dynamic thread vector, tcbhead_t.dtv points to the first dtv which is a generation counter.
// dtv[1..n] is the tls space for the executable and each loaded shared object
typedef union dtv
{
  unsigned long counter;
  struct dtv_pointer pointer;
} dtv_t;

// sysdeps/x86_64/dl-tls.h

// Thus a pointer to a TLS variable defined in a module id `ti_module`
// would be *(dtv[tls_index.ti_module].pointer + tls_index.ti_offset);
typedef unsigned long uint64_t;
typedef struct
{
  uint64_t ti_module;
  uint64_t ti_offset;
} tls_index;

#endif /* _STAPLINUX_TLS_H_ */
