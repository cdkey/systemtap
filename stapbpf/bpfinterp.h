/* bpfinterp.h - SystemTap BPF interpreter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2016-2019 Red Hat, Inc.
 *
 */

#ifndef BPFINTERP_H
#define BPFINTERP_H 1

#include <sys/types.h>
#include <inttypes.h>
#include <linux/bpf.h>

extern "C" {
#include "libbpf.h"
}

// Required constants such as BPF_MAXFORMATLEN:
#include "../bpf-internal.h"

// Used by the transport layer and interpreter:
struct bpf_transport_context {
  // XXX: The following two fields are only used for kernel programs.
  // pmu_fd == -1 indicates context for a userspace interpreter.
  unsigned cpu;
  int pmu_fd;

  // References to global state:
  unsigned ncpus;
  bpf_map_def *map_attrs;
  std::vector<int> *map_fds;
  FILE *output_f;
  std::vector<std::string> *interned_strings;
  std::unordered_map<bpf::globals::agg_idx, bpf::globals::stats_map> *aggregates;
  // XXX: Could be refactored into a single global struct bpf_global_context.
  
  // Data for procfs probes. Multiple threads will be accessing this variable.
  // However, the procfs_lock should prevent any concurrency issues.
  std::string procfs_msg;

  // Data for an in-progress printf request:
  bool in_printf;
  int format_no;          // -- index into table of interned strings
  unsigned expected_args; // -- expected number of printf_args
  std::vector<void *> printf_args;
  std::vector<bpf::globals::perf_event_type> printf_arg_types; // either ..ARG_LONG or ..ARG_STR

  // TODO: Takes a lot of arguments. Refactor to be less unwieldy.
  bpf_transport_context(unsigned cpu, int pmu_fd, unsigned ncpus,
                        bpf_map_def *map_attrs,
                        std::vector<int> *map_fds,
                        FILE *output_f,
                        std::vector<std::string> *interned_strings,
                        std::unordered_map<bpf::globals::agg_idx,
                                           bpf::globals::stats_map> *aggregates)
    : cpu(cpu), pmu_fd(pmu_fd), ncpus(ncpus),
      map_attrs(map_attrs), map_fds(map_fds), output_f(output_f),
      interned_strings(interned_strings), aggregates(aggregates),
      in_printf(false), format_no(-1), expected_args(0) {}
};

enum bpf_perf_event_ret bpf_handle_transport_msg(void *buf, size_t size,
                                                 bpf_transport_context *ctx);
  
uint64_t bpf_interpret(size_t ninsns,
                       const struct bpf_insn insns[],
                       bpf_transport_context *ctx);

extern int target_pid;

#endif /* STAPRUNBPF_H */
