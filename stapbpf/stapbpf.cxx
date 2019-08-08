/* stapbpf.cxx - SystemTap BPF loader
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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <cassert>
#include <csignal>
#include <cerrno>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <unistd.h>
#include <limits.h>
#include <inttypes.h>
#include <getopt.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include "bpfinterp.h"
#include "../util.h"

extern "C" {
#include <linux/bpf.h>
#include <linux/perf_event.h>
/* Introduced in 4.1. */
#ifndef PERF_EVENT_IOC_SET_BPF
#define PERF_EVENT_IOC_SET_BPF _IOW('$', 8, __u32)
#endif
#include <libelf.h>
}

#include "config.h"
#include "../git_version.h"
#include "../version.h"
#include "../bpf-internal.h"

#ifndef EM_BPF
#define EM_BPF 0xeb9f
#endif
#ifndef R_BPF_MAP_FD
#define R_BPF_MAP_FD 1
#endif

using namespace std;

static int group_fd = -1;		// ??? Need one per cpu.
extern "C" { 
int log_level = 0;
};
int target_pid = 0;
static int warnings = 1;
static int exit_phase = 0;
static int interrupt_message = 0;
static FILE *output_f = stdout;
static FILE *kmsg = NULL;

static const char *module_name;
static const char *module_basename;
static const char *script_name; // name of original systemtap script
static const char *module_license;

static const char *user;  // username
static std::string prefix; // used to create procfs-like probe directory

static Elf *module_elf;

static uint32_t kernel_version;

// Locks for accessing procfs-like probe messages
std::mutex procfs_lock;

// Sized by the contents of the "maps" section.
static bpf_map_def *map_attrs;
static std::vector<int> map_fds;

// PR24543: Some perf constructs must be anchored to a single CPU.
// Normally we use cpu0, but it could (in very rare cases) be disabled.
// Initialized in mark_active_cpus() along with cpu_online.
static int default_cpu = 0;

// Sized by the number of CPUs:
static std::vector<int> perf_fds;
static std::vector<bool> cpu_online; // -- is CPU active?
static std::vector<struct perf_event_mmap_page *> perf_headers;
static std::vector<bpf_transport_context *> transport_contexts;

// Additional info for perf_events transport:
static int perf_event_page_size;
static int perf_event_page_count = 8;
static int perf_event_mmap_size;

// Table of interned strings:
static std::vector<std::string> interned_strings;

// Table of map id's for statistical aggregates:
static std::unordered_map<bpf::globals::agg_idx, bpf::globals::stats_map> aggregates;

// XXX: Required static data and methods from bpf::globals, shared with translator.
#include "../bpf-shared-globals.h"

// Sized by the number of sections, so that we can easily
// look them up by st_shndx.
static std::vector<int> prog_fds;

// Programs to run at begin and end of execution.
static Elf_Data *prog_begin;
static Elf_Data *prog_end;

#define DEBUGFS		"/sys/kernel/debug/tracing/"
#define KPROBE_EVENTS	DEBUGFS "kprobe_events"
#define UPROBE_EVENTS   DEBUGFS "uprobe_events"
#define EVENTS          DEBUGFS "events"

#define CPUFS         "/sys/devices/system/cpu/"
#define CPUS_ONLINE   CPUFS "online"
#define CPUS_POSSIBLE CPUFS "possible"

static void unregister_kprobes(const size_t nprobes);

struct procfsprobe_data
{
  std::string path;
  uint64_t umask;
  char type; // either 'r' (read) or 'w' (write)
  uint64_t maxsize_val;
  Elf_Data* read_prog;
  std::vector<Elf_Data*> write_prog;
  
  // ctor for read probes
  procfsprobe_data(string path, uint64_t umask, char type, uint64_t maxsize_val, Elf_Data* prog) 
    : path(path), umask(umask), type(type), maxsize_val(maxsize_val), read_prog(prog)
  { assert (type == 'r'); }

  // ctor for write probes
  procfsprobe_data(string path, uint64_t umask, char type, uint64_t maxsize_val, std::vector<Elf_Data*> prog)
    : path(path), umask(umask), type(type), maxsize_val(maxsize_val), write_prog(prog)
  { assert (type == 'w'); }
};


struct kprobe_data
{
  string args;
  char type;
  int prog_fd;
  int event_id;
  int event_fd;				// ??? Need one per cpu.

  kprobe_data(char t, string s, int fd)
    : args(s), type(t), prog_fd(fd), event_id(-1), event_fd(-1)
  { }
};

struct uprobe_data
{
  string path;
  char type;
  int pid;
  unsigned long long offset;
  int prog_fd;
  int event_id;
  int event_fd;

  uprobe_data(string path, char t, int pid, unsigned long long off, int fd)
    : path(path), type(t), pid(pid), offset(off), prog_fd(fd),
      event_id(-1), event_fd(-1)
  { }
};

struct timer_data
{
  unsigned long period;
  int prog_fd;
  int event_fd;

  timer_data(unsigned long period, int fd)
    : period(period), prog_fd(fd), event_fd(-1)
  { }
};

struct perf_data
{
  int event_type;
  int event_config;
  bool has_freq;
  unsigned long interval;
  int prog_fd;
  int event_fd;

  perf_data(int type, int config, bool freq, unsigned long interval, int fd)
    : event_type(type), event_config(config), has_freq(freq),
      interval(interval), prog_fd(fd), event_fd(-1)
  { }
};

struct trace_data
{
  string system;
  string name;
  int prog_fd;
  int event_id;
  int event_fd;

  trace_data(char *s, char *n, int fd)
    : system(s), name(n), prog_fd(fd), event_id(-1), event_fd(-1)
  { }
};

static std::vector<procfsprobe_data> procfsprobes;
static std::vector<kprobe_data> kprobes;
static std::vector<timer_data> timers;
static std::vector<perf_data> perf_probes;
static std::vector<trace_data> tracepoint_probes;
static std::vector<trace_data> raw_tracepoint_probes;
static std::vector<uprobe_data> uprobes;

// TODO: Move fatal() to bpfinterp.h and replace abort() calls in the interpreter.
// TODO: Add warn() option.
static void __attribute__((noreturn))
fatal(const char *str, ...)
{
  if (module_name)
    fprintf(stderr, "Error loading %s: ", module_name);

  va_list va;
  va_start(va, str);
  vfprintf(stderr, str, va);
  va_end(va);
  
  exit(1);
}

static void
fatal_sys()
{
  fatal("%s\n", strerror(errno));
}

static void
fatal_elf()
{
  fatal("%s\n", elf_errmsg(-1));
}

// XXX: based on get_online_cpus()/read_cpu_range()
// in bcc src/cc/common.cc
//
// PR24543: Also sets default_cpu.
//
// This is the only way I know of so far, so I have to imitate it for
// now. Parsing a /sys/devices diagnostic file seems a bit brittle to
// me, though.
static void
mark_active_cpus(unsigned ncpus)
{
  std::ifstream cpu_ranges(CPUS_ONLINE);
  std::string cpu_range;

  // XXX if cpu0 is offline
  int alternate_cpu = -1;
  bool found_alternate = false;

  cpu_online.clear();
  for (unsigned i = 0; i < ncpus; i++)
    cpu_online.push_back(false);

  while (std::getline(cpu_ranges, cpu_range, ','))
    {
      size_t rangepos = cpu_range.find("-");
      int start, end;
      if (rangepos == std::string::npos)
        {
          start = end = std::stoi(cpu_range);
        }
      else
        {
          start = std::stoi(cpu_range.substr(0, rangepos));
          end = std::stoi(cpu_range.substr(rangepos+1));
        }
      for (int i = start; i <= end; i++)
        {
          if (!found_alternate)
            {
              alternate_cpu = i;
              found_alternate = true;
            }
          cpu_online[i] = true;
        }
    }

  // PR24543: Make sure default_cpu is active.
  if (!cpu_online[default_cpu] && found_alternate)
    default_cpu = alternate_cpu;
}

static int
count_active_cpus()
{
  int count = 0;
  for (unsigned cpu = 0; cpu < cpu_online.size(); cpu++)
    if (cpu_online[cpu])
      count++;
  return count;
}

static int
create_group_fds()
{
  perf_event_attr peattr;

  memset(&peattr, 0, sizeof(peattr));
  peattr.size = sizeof(peattr);
  peattr.disabled = 1;
  peattr.type = PERF_TYPE_SOFTWARE;
  peattr.config = PERF_COUNT_SW_DUMMY;

  return group_fd = perf_event_open(&peattr, -1, default_cpu, -1, 0);
}

static void
instantiate_maps (Elf64_Shdr *shdr, Elf_Data *data)
{
  if (shdr->sh_entsize != sizeof(bpf_map_def))
    fatal("map entry size mismatch (%zu != %zu)\n",
	  (size_t)shdr->sh_entsize, sizeof(bpf_map_def));

  size_t i, n = shdr->sh_size / sizeof(bpf_map_def);
  struct bpf_map_def *attrs = static_cast<bpf_map_def *>(data->d_buf);

  map_attrs = attrs;
  map_fds.assign(n, -1);

  // XXX: PR24324 -- This overhead space calculation was too
  // conservative and caused resource exhaustion errors, disabling it
  // until we figure out how much space we need or if the
  // RLIM_INFINITY solution below is adequate.
#if 0
  /* First, make room for the maps in this process' RLIMIT_MEMLOCK: */
  size_t rlimit_increase = 0;
  for (i = 0; i < n; ++i)
    {
      // TODO: The 58 bytes of overhead space per entry has been
      // decided by trial and error, and may require further tweaking:
      rlimit_increase += (58 + attrs[i].key_size + attrs[i].value_size) * attrs[i].max_entries;
      // TODO: Note that Certain Other Tools just give up on
      // calculating and set rlimit to the maximum possible.
    }
#endif

  struct rlimit curr_rlimit;
  int rc;

  rc = getrlimit(RLIMIT_MEMLOCK, &curr_rlimit);
  if (rc < 0)
    fatal("could not get map resource limit: %s\n",
          strerror(errno));

  rlim_t rlim_orig = curr_rlimit.rlim_cur;
  rlim_t rlim_max_orig = curr_rlimit.rlim_max;
#if 0
  curr_rlimit.rlim_cur += rlimit_increase;
  curr_rlimit.rlim_max += rlimit_increase;
  if (curr_rlimit.rlim_cur < rlim_orig) // handle overflow
    curr_rlimit.rlim_cur = rlim_orig;
  if (curr_rlimit.rlim_max < rlim_max_orig) // handle overflow
    curr_rlimit.rlim_max = rlim_max_orig;
#endif
  // TODOXXX: PR24324 -- EXPERIMENTAL fix for aggressive resource limits.
  // Other Tools do something like this but it doesn't solve all our problems.
  curr_rlimit.rlim_cur = RLIM_INFINITY;
  curr_rlimit.rlim_max = RLIM_INFINITY;

  rc = setrlimit(RLIMIT_MEMLOCK, &curr_rlimit);
  if (rc < 0)
    fatal("could not increase map resource limit -- "
          "cur from %lu to %lu, max from %lu to %lu: %s\n",
          rlim_orig, curr_rlimit.rlim_cur,
          rlim_max_orig, curr_rlimit.rlim_max,
          strerror(errno));
  if (log_level > 1)
    {
      fprintf(stderr, "increasing map cur resource limit from %lu to %lu\n",
              rlim_orig, curr_rlimit.rlim_cur);
      fprintf(stderr, "increasing map max resource limit from %lu to %lu\n",
              rlim_max_orig, curr_rlimit.rlim_max);
    }

  /* Now create the maps: */
  for (i = 0; i < n; ++i)
    {
      /* PR22330: The perf_event_map used for message transport must
         have max_entries equal to the number of active CPUs, which we
         wouldn't know for sure at translate time. Set it now: */
      bpf_map_type map_type = static_cast<bpf_map_type>(attrs[i].type);
      if (map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY)
        {
          /* XXX: Assume our only perf_event_map is the percpu transport one: */
          assert(i == bpf::globals::perf_event_map_idx);
          assert(attrs[i].max_entries == bpf::globals::NUM_CPUS_PLACEHOLDER);

          // TODO: perf_event buffers can only be created for currently
          // active CPUs. For now we imitate Certain Other Tools and
          // create perf_events for CPUs that are active at startup time
          // (while sizing the perf_event_map according to total CPUs).
          // But for full coverage, we really need to listen to CPUs
          // coming on/offline and adjust accordingly.
          long ncpus_ = sysconf(_SC_NPROCESSORS_CONF);
          unsigned ncpus = ncpus_ > 0 ? ncpus_ : 1;
          if (ncpus_ < 0)
            fprintf(stderr, "WARNING: could not get number of CPUs, falling back to 1: %s\n", strerror(errno));
          else if (ncpus_ == 0)
            fprintf(stderr, "WARNING: could not get number of CPUs, falling back to 1\n"); // XXX no errno
          //unsigned ncpus = get_nprocs_conf();
          mark_active_cpus((unsigned)ncpus);
          attrs[i].max_entries = ncpus;
        }

      if (log_level > 2)
        fprintf(stderr, "creating map type %u entry %zu: key_size %u, value_size %u, "
                "max_entries %u, map_flags %u\n", map_type, i,
                attrs[i].key_size, attrs[i].value_size,
                attrs[i].max_entries, attrs[i].map_flags);
      int fd = bpf_create_map(static_cast<bpf_map_type>(attrs[i].type),
			      attrs[i].key_size, attrs[i].value_size,
			      attrs[i].max_entries, attrs[i].map_flags);
      if (fd < 0)
	fatal("map entry %zu: %s\n", i, strerror(errno));
      map_fds[i] = fd;
    }
}

static int
prog_load(Elf_Data *data, const char *name)
{
  enum bpf_prog_type prog_type;

  if (strncmp(name, "kprobe", 6) == 0)
    prog_type = BPF_PROG_TYPE_KPROBE;
  else if (strncmp(name, "kretprobe", 9) == 0)
    prog_type = BPF_PROG_TYPE_KPROBE;
  else if (strncmp(name, "uprobe", 6) == 0)
    prog_type = BPF_PROG_TYPE_KPROBE;
  else if (strncmp(name, "timer", 5) == 0)
    prog_type = BPF_PROG_TYPE_PERF_EVENT;
  else if (strncmp(name, "trace", 5) == 0)
    prog_type = BPF_PROG_TYPE_TRACEPOINT;
#ifdef HAVE_BPF_PROG_TYPE_RAW_TRACEPOINT
  else if (strncmp(name, "raw_trace", 9) == 0)
    prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
#endif
  else if (strncmp(name, "perf", 4) == 0)
    {
      if (name[5] == '2' && name[6] == '/')
        prog_type = BPF_PROG_TYPE_TRACEPOINT;
      else
        prog_type = BPF_PROG_TYPE_PERF_EVENT;
    }
  else
    fatal("unhandled program type for section \"%s\"\n", name);

  if (data->d_size % sizeof(bpf_insn))
    fatal("program size not a multiple of %zu\n", sizeof(bpf_insn));

  if (kmsg != NULL)
    {
      fprintf (kmsg, "%s (%s): stapbpf: %s, name: %s, d_size: %lu\n",
               module_basename, script_name, VERSION, name, (unsigned long)data->d_size);
      fflush (kmsg); // Otherwise, flush will only happen after the prog runs.
    }
  int fd = bpf_prog_load(prog_type, static_cast<bpf_insn *>(data->d_buf),
			 data->d_size, module_license, kernel_version);
  if (fd < 0)
    {
      if (bpf_log_buf[0] != 0)
	fatal("bpf program load failed: %s\n%s\n",
	      strerror(errno), bpf_log_buf);
      else
	fatal("bpf program load failed: %s\n", strerror(errno));
    }
  return fd;
}

static void
prog_relocate(Elf_Data *prog_data, Elf_Data *rel_data,
	      Elf_Data *sym_data, Elf_Data *str_data,
	      const char *prog_name, unsigned maps_idx, bool allocated)
{
  bpf_insn *insns = static_cast<bpf_insn *>(prog_data->d_buf);
  Elf64_Rel *rels = static_cast<Elf64_Rel *>(rel_data->d_buf);
  Elf64_Sym *syms = static_cast<Elf64_Sym *>(sym_data->d_buf);

  if (prog_data->d_size % sizeof(bpf_insn))
    fatal("program size not a multiple of %zu\n", sizeof(bpf_insn));
  if (rel_data->d_type != ELF_T_REL
      || rel_data->d_size % sizeof(Elf64_Rel))
    fatal("invalid reloc metadata\n");
  if (sym_data->d_type != ELF_T_SYM
      || sym_data->d_size % sizeof(Elf64_Sym))
    fatal("invalid symbol metadata\n");

  size_t psize = prog_data->d_size;
  size_t nrels = rel_data->d_size / sizeof(Elf64_Rel);
  size_t nsyms = sym_data->d_size / sizeof(Elf64_Sym);

  for (size_t i = 0; i < nrels; ++i)
    {
      uint32_t sym = ELF64_R_SYM(rels[i].r_info);
      uint32_t type = ELF64_R_TYPE(rels[i].r_info);
      unsigned long long r_ofs = rels[i].r_offset;
      size_t fd_idx;

      if (type != R_BPF_MAP_FD)
	fatal("invalid relocation type %u\n", type);
      if (sym >= nsyms)
	fatal("invalid symbol index %u\n", sym);
      if (r_ofs >= psize || r_ofs % sizeof(bpf_insn))
	fatal("invalid relocation offset at %s+%llu\n", prog_name, r_ofs);

      if (sym >= nsyms)
	fatal("invalid relocation symbol %u\n", sym);
      if (syms[sym].st_shndx != maps_idx
	  || syms[sym].st_value % sizeof(bpf_map_def)
	  || (fd_idx = syms[sym].st_value / sizeof(bpf_map_def),
	      fd_idx >= map_fds.size()))
	{
	  const char *name = "";
	  if (syms[sym].st_name < str_data->d_size)
	    name = static_cast<char *>(str_data->d_buf) + syms[sym].st_name;
	  if (*name)
	    fatal("symbol %s does not reference a map\n", name);
	  else
	    fatal("symbol %u does not reference a map\n", sym);
	}

      bpf_insn *insn = insns + (r_ofs / sizeof(bpf_insn));
      if (insn->code != (BPF_LD | BPF_IMM | BPF_DW))
	fatal("invalid relocation insn at %s+%llu\n", prog_name, r_ofs);

      insn->src_reg = BPF_PSEUDO_MAP_FD;
      insn->imm = (allocated ? map_fds[fd_idx] : fd_idx);
    }
}

static void
maybe_collect_kprobe(const char *name, unsigned name_idx,
		     unsigned fd_idx, Elf64_Addr offset)
{
  char type;
  string arg;

  if (strncmp(name, "kprobe/", 7) == 0)
    {
      string line;
      const char *stext = NULL;
      type = 'p';
      name += 7;

      ifstream syms("/proc/kallsyms");
      if (!syms)
        fatal("error opening /proc/kallsyms: %s\n", strerror(errno));

      // get value of symbol _stext and add it to the offset found in name.
      while (getline(syms, line))
        {
          const char *l = line.c_str();
          if (strncmp(l + 19, "_stext", 6) == 0)
            {
              stext = l;
              break;
            }
        }

      if (stext == NULL)
        fatal("could not find _stext in /proc/kallsyms");

      unsigned long addr = strtoul(stext, NULL, 16);
      addr += strtoul(name, NULL, 16);
      stringstream ss;
      ss << "0x" << hex << addr;
      arg = ss.str();
    }
  else if (strncmp(name, "kretprobe/", 10) == 0)
    type = 'r', arg = name + 10; 
  else
    return;

  int fd = -1;
  if (fd_idx >= prog_fds.size() || (fd = prog_fds[fd_idx]) < 0)
    fatal("probe %u section %u not loaded\n", name_idx, fd_idx);
  if (offset != 0)
    fatal("probe %u offset non-zero\n", name_idx);

  kprobes.push_back(kprobe_data(type, arg, fd));
}

static void
collect_procfsprobe(const char *name, Elf_Data* prog) 
{
  uint64_t umask; 
  uint64_t maxsize_val;
  char type;
  char fifoname[PATH_MAX];

  int res = sscanf(name, "procfsprobe/%lu/%c/%lu/%s", &umask, &type, &maxsize_val, fifoname);

  if (res != 4)
    fatal("unable to parse name of probe: %s", name);

  std::string path(fifoname); 

  if (type == 'r')
    procfsprobes.push_back(procfsprobe_data(path, umask, type, maxsize_val, prog));
  else 
    {
      // Check if a write probe with the same path already exists 
      for (unsigned i = 0; i < procfsprobes.size(); i++)
        if (procfsprobes[i].path == string(path) && procfsprobes[i].type == 'w') 
          {
            procfsprobes[i].write_prog.push_back(prog);
            return;
          }

      std::vector<Elf_Data*> progs;
      progs.push_back(prog);
      procfsprobes.push_back(procfsprobe_data(path, umask, type, maxsize_val, progs));
    }
}

static void
collect_uprobe(const char *name, unsigned name_idx, unsigned fd_idx)
{
  char type = '\0';
  int pid = -1;
  unsigned long long off = 0;
  char path[PATH_MAX];

  int res = sscanf(name, "uprobe/%c/%d/%llu%s", &type, &pid, &off, path);

  if (!pid)
    pid = -1; // indicates to perf_event_open that we're tracing all processes

  if (res != 4)
    fatal("unable to parse name of probe %u section %u\n", name_idx, fd_idx);

  int fd = -1;
  if (fd_idx >= prog_fds.size() || (fd = prog_fds[fd_idx]) < 0)
    fatal("probe %u section %u not loaded\n", name_idx, fd_idx);

  uprobes.push_back(uprobe_data(std::string(path), type, pid, off, fd));
}

static void
collect_perf(const char *name, unsigned name_idx, unsigned fd_idx)
{
  char has_freq;
  int event_type;
  int event_config;
  unsigned long interval;

  int res = sscanf(name, "perf/%d/%d/%c/%lu",
                   &event_type, &event_config, &has_freq, &interval);
  if (res != 4)
    fatal("unable to parse name of probe %u section %u\n", name_idx, fd_idx);

  int fd = -1;
  if (fd_idx >= prog_fds.size() || (fd = prog_fds[fd_idx]) < 0)
    fatal("probe %u section %u not loaded\n", name_idx, fd_idx);

  perf_probes.push_back(
    perf_data(event_type, event_config, has_freq == 'f', interval, fd));
}

static void
collect_timer(const char *name, unsigned name_idx, unsigned fd_idx)
{
  unsigned long period = strtoul(name + 11, NULL, 10);

  if (strncmp(name + 6, "jiff/", 5) == 0)
    {
      long jiffies_per_sec = sysconf(_SC_CLK_TCK);
      period *= 1e9 / jiffies_per_sec;
    }

  int fd = -1;
  if (fd_idx >= prog_fds.size() || (fd = prog_fds[fd_idx]) < 0)
    fatal("probe %u section %u not loaded\n", name_idx, fd_idx);

  timers.push_back(timer_data(period, fd));
  return;
}

static void
collect_tracepoint(const char *name, unsigned name_idx, unsigned fd_idx)
{
  char tp_system[512];
  char tp_name[512];

  int res = sscanf(name, "trace/%[^/]/%s", tp_system, tp_name);
  if (res != 2 || strlen(name) > 512)
    fatal("unable to parse name of probe %u section %u\n", name_idx, fd_idx);

  int fd = -1;
  if (fd_idx >= prog_fds.size() || (fd = prog_fds[fd_idx]) < 0)
    fatal("probe %u section %u not loaded\n", name_idx, fd_idx);

  tracepoint_probes.push_back(trace_data(tp_system, tp_name, fd));
}

static void
collect_raw_tracepoint(const char *name, unsigned name_idx, unsigned fd_idx)
{
  char tp_system[512];
  char tp_name[512];

  int res = sscanf(name, "raw_trace/%[^/]/%s", tp_system, tp_name);
  if (res != 2 || strlen(name) > 512)
    fatal("unable to parse name of probe %u section %u\n", name_idx, fd_idx);

  int fd = -1;
  if (fd_idx >= prog_fds.size() || (fd = prog_fds[fd_idx]) < 0)
    fatal("probe %u section %u not loaded\n", name_idx, fd_idx);

  raw_tracepoint_probes.push_back(trace_data(tp_system, tp_name, fd));
}

static void
kprobe_collect_from_syms(Elf_Data *sym_data, Elf_Data *str_data)
{
  Elf64_Sym *syms = static_cast<Elf64_Sym *>(sym_data->d_buf);
  size_t nsyms = sym_data->d_type / sizeof(Elf64_Sym);

  if (sym_data->d_type != ELF_T_SYM
      || sym_data->d_size % sizeof(Elf64_Sym))
    fatal("invalid kprobes symbol metadata\n");

  for (size_t i = 0; i < nsyms; ++i)
    {
      const char *name;
      if (syms[i].st_name < str_data->d_size)
	name = static_cast<char *>(str_data->d_buf) + syms[i].st_name;
      else
	fatal("symbol %u has invalid string index\n", i);
      maybe_collect_kprobe(name, i, syms[i].st_shndx, syms[i].st_value);
    }
}

static void
unregister_uprobes(const size_t nprobes)
{
   if (nprobes == 0)
    return;

  int fd = open(DEBUGFS "uprobe_events", O_WRONLY);
  if (fd < 0)
    return;


  const int pid = getpid();
  for (size_t i = 0; i < nprobes; ++i)
    {
      close(uprobes[i].event_fd);

      char msgbuf[128];
      ssize_t olen = snprintf(msgbuf, sizeof(msgbuf), "-:stapprobe_%d_%zu",
			      pid, i);
      ssize_t wlen = write(fd, msgbuf, olen);
      if (wlen < 0)
	fprintf(stderr, "Error removing probe %zu: %s\n",
		i, strerror(errno));
    }
  close(fd);
}

static void
register_uprobes()
{
  size_t nprobes = uprobes.size();
  if (nprobes == 0)
    return;

  int fd = open(UPROBE_EVENTS, O_WRONLY);
  if (fd < 0)
    fatal("Error opening %s: %s\n", UPROBE_EVENTS, strerror(errno));

  const int pid = getpid();

  for (size_t i = 0; i < nprobes; ++i)
    {
      uprobe_data &u = uprobes[i];
      char msgbuf[PATH_MAX];

      ssize_t olen = snprintf(msgbuf, sizeof(msgbuf), "%c:stapprobe_%d_%zu %s:0x%llx",
			      u.type, pid, i, u.path.c_str(), u.offset);
      if ((size_t)olen >= sizeof(msgbuf))
	{
	  fprintf(stderr, "Buffer overflow creating probe %zu\n", i);
	  if (i == 0)
	    goto fail_0;
	  nprobes = i - 1;
	  goto fail_n;
	}

      if (log_level > 1)
        fprintf(stderr, "Associating probe %zu with uprobe %s\n", i, msgbuf);

      ssize_t wlen = write(fd, msgbuf, olen);
      if (wlen != olen)
	{
	  fprintf(stderr, "Error creating probe %zu: %s\n",
		  i, strerror(errno));
	  if (i == 0)
	    goto fail_0;
	  nprobes = i - 1;
	  goto fail_n;
	}
    }
  close(fd);

  for (size_t i = 0; i < nprobes; ++i)
    {
      char fnbuf[PATH_MAX];
      ssize_t len = snprintf(fnbuf, sizeof(fnbuf),
			     DEBUGFS "events/uprobes/stapprobe_%d_%zu/id", pid, i);
      if ((size_t)len >= sizeof(bpf_log_buf))
	{
	  fprintf(stderr, "Buffer overflow creating probe %zu\n", i);
	  goto fail_n;
	}

      fd = open(fnbuf, O_RDONLY);
      if (fd < 0)
	{
	  fprintf(stderr, "Error opening probe event id %zu: %s\n",
		  i, strerror(errno));
	  goto fail_n;
	}

      char msgbuf[128];
      len = read(fd, msgbuf, sizeof(msgbuf) - 1);
      if (len < 0)
	{
	  fprintf(stderr, "Error reading probe event id %zu: %s\n",
		  i, strerror(errno));
	  goto fail_n;
	}
      close(fd);

      msgbuf[len] = 0;
      uprobes[i].event_id = atoi(msgbuf);
    }

  // ??? Iterate to enable on all cpus, each with a different group_fd.
  {
    perf_event_attr peattr;

    memset(&peattr, 0, sizeof(peattr));
    peattr.size = sizeof(peattr);
    peattr.type = PERF_TYPE_TRACEPOINT;
    peattr.sample_type = PERF_SAMPLE_RAW;
    peattr.sample_period = 1;
    peattr.wakeup_events = 1;

    for (size_t i = 0; i < nprobes; ++i)
      {
	uprobe_data &u = uprobes[i];
        peattr.config = u.event_id;

        fd = perf_event_open(&peattr, u.pid, default_cpu, -1, 0);
        if (fd < 0)
	  {
	    fprintf(stderr, "Error opening probe id %zu: %s\n",
		    i, strerror(errno));
	    goto fail_n;
	  }
        u.event_fd = fd;

        if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, u.prog_fd) < 0)
	  {
	    fprintf(stderr, "Error installing bpf for probe id %zu: %s\n",
		    i, strerror(errno));
	    goto fail_n;
	  }
      }
  }
  return;

 fail_n:
  unregister_uprobes(nprobes);
 fail_0:
  exit(1);
}

static void
register_kprobes()
{
  size_t nprobes = kprobes.size();
  if (nprobes == 0)
    return;
    
  int fd = open(KPROBE_EVENTS, O_WRONLY);
  if (fd < 0)
    fatal("Error opening %s: %s\n", KPROBE_EVENTS, strerror(errno));

  const int pid = getpid();

  for (size_t i = 0; i < nprobes; ++i)
    {
      kprobe_data &k = kprobes[i];
      char msgbuf[128];
      
      ssize_t olen = snprintf(msgbuf, sizeof(msgbuf), "%c:p%d_%zu %s",
			      k.type, pid, i, k.args.c_str());
      if ((size_t)olen >= sizeof(msgbuf))
	{
	  fprintf(stderr, "Buffer overflow creating probe %zu\n", i);
	  if (i == 0)
	    goto fail_0;
	  nprobes = i - 1;
	  goto fail_n;
	}

      if (log_level > 1)
        fprintf(stderr, "Associating probe %zu with kprobe %s\n", i, msgbuf);
      
      ssize_t wlen = write(fd, msgbuf, olen);
      if (wlen != olen)
	{
	  fprintf(stderr, "Error creating probe %zu: %s\n",
		  i, strerror(errno));
	  if (i == 0)
	    goto fail_0;
	  nprobes = i - 1;
	  goto fail_n;
	}
    }
  close(fd);

  for (size_t i = 0; i < nprobes; ++i)
    {
      char fnbuf[PATH_MAX];
      ssize_t len = snprintf(fnbuf, sizeof(fnbuf),
			     DEBUGFS "events/kprobes/p%d_%zu/id", pid, i);
      if ((size_t)len >= sizeof(bpf_log_buf))
	{
	  fprintf(stderr, "Buffer overflow creating probe %zu\n", i);
	  goto fail_n;
	}

      fd = open(fnbuf, O_RDONLY);
      if (fd < 0)
	{
	  fprintf(stderr, "Error opening probe event id %zu: %s\n",
		  i, strerror(errno));
	  goto fail_n;
	}

      char msgbuf[128];
      len = read(fd, msgbuf, sizeof(msgbuf) - 1);
      if (len < 0)
	{
	  fprintf(stderr, "Error reading probe event id %zu: %s\n",
		  i, strerror(errno));
	  goto fail_n;
	}
      close(fd);

      msgbuf[len] = 0;
      kprobes[i].event_id = atoi(msgbuf);
    }

  // ??? Iterate to enable on all cpus, each with a different group_fd.
  {
    perf_event_attr peattr;

    memset(&peattr, 0, sizeof(peattr));
    peattr.size = sizeof(peattr);
    peattr.type = PERF_TYPE_TRACEPOINT;
    peattr.sample_type = PERF_SAMPLE_RAW;
    peattr.sample_period = 1;
    peattr.wakeup_events = 1;

    for (size_t i = 0; i < nprobes; ++i)
      {
	kprobe_data &k = kprobes[i];
        peattr.config = k.event_id;

        fd = perf_event_open(&peattr, -1, default_cpu, group_fd, 0);
        if (fd < 0)
	  {
	    fprintf(stderr, "Error opening probe id %zu: %s\n",
		    i, strerror(errno));
	    goto fail_n;
	  }
        k.event_fd = fd;

        if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, k.prog_fd) < 0)
	  {
	    fprintf(stderr, "Error installing bpf for probe id %zu: %s\n",
		    i, strerror(errno));
	    goto fail_n;
	  }
      }
  }
  return;

 fail_n:
  unregister_kprobes(nprobes);
 fail_0:
  exit(1);
}

static void
unregister_kprobes(const size_t nprobes)
{
  if (nprobes == 0)
    return;

  int fd = open(DEBUGFS "kprobe_events", O_WRONLY);
  if (fd < 0)
    return;


  const int pid = getpid();
  for (size_t i = 0; i < nprobes; ++i)
    {
      close(kprobes[i].event_fd);

      char msgbuf[128];
      ssize_t olen = snprintf(msgbuf, sizeof(msgbuf), "-:p%d_%zu",
			      pid, i);
      ssize_t wlen = write(fd, msgbuf, olen);
      if (wlen < 0)
	fprintf(stderr, "Error removing probe %zu: %s\n",
		i, strerror(errno));
    }
  close(fd);
}

static void
unregister_tracepoints(const size_t nprobes)
{
  for (size_t i = 0; i < nprobes; ++i)
    close(tracepoint_probes[i].event_fd);
}

static void
unregister_raw_tracepoints(const size_t nprobes)
{
  for (size_t i = 0; i < nprobes; ++i)
    close(raw_tracepoint_probes[i].event_fd);
}

static void
register_tracepoints()
{
  size_t nprobes = tracepoint_probes.size();
  if (nprobes == 0)
    return;

  for (size_t i = 0; i < nprobes; ++i)
    {
      trace_data &t = tracepoint_probes[i];
      char fnbuf[PATH_MAX];
      ssize_t len = snprintf(fnbuf, sizeof(fnbuf),
			     DEBUGFS "events/%s/%s/id",
                             t.system.c_str(), t.name.c_str());
      if ((size_t)len >= sizeof(bpf_log_buf))
	{
	  fprintf(stderr, "Buffer overflow creating probe %zu\n", i);
	  goto fail;
	}

      int fd = open(fnbuf, O_RDONLY);
      if (fd < 0)
	{
	  fprintf(stderr, "Error opening probe event id %zu: %s\n",
		  i, strerror(errno));

          if (errno == ENOENT)
            fprintf(stderr, "\"%s/%s\" could not be found in %s\n",
                    t.system.c_str(), t.name.c_str(), EVENTS);

	  goto fail;
	}

      char msgbuf[128];
      len = read(fd, msgbuf, sizeof(msgbuf) - 1);
      if (len < 0)
	{
	  fprintf(stderr, "Error reading probe event id %zu: %s\n",
		  i, strerror(errno));
          close(fd);
	  goto fail;
	}
      close(fd);

      msgbuf[len] = 0;
      t.event_id = atoi(msgbuf);
    }

  // ??? Iterate to enable on all cpus, each with a different group_fd.
  {
    perf_event_attr peattr;

    memset(&peattr, 0, sizeof(peattr));
    peattr.size = sizeof(peattr);
    peattr.type = PERF_TYPE_TRACEPOINT;
    peattr.sample_type = PERF_SAMPLE_RAW;
    peattr.sample_period = 1;
    peattr.wakeup_events = 1;

    for (size_t i = 0; i < nprobes; ++i)
      {
	trace_data &t = tracepoint_probes[i];
        peattr.config = t.event_id;

        int fd = perf_event_open(&peattr, -1, default_cpu, group_fd, 0);
        if (fd < 0)
	  {
	    fprintf(stderr, "Error opening probe id %zu: %s\n",
		    i, strerror(errno));
	    goto fail;
	  }
        t.event_fd = fd;

        if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, t.prog_fd) < 0)
	  {
	    fprintf(stderr, "Error installing bpf for probe id %zu: %s\n",
		    i, strerror(errno));
	    goto fail;
	  }
      }
  }
  return;

 fail:
  unregister_tracepoints(nprobes);
  exit(1);
}

static void
register_raw_tracepoints()
{
  size_t nprobes = raw_tracepoint_probes.size();
  if (nprobes == 0)
    return;

#ifndef HAVE_BPF_PROG_TYPE_RAW_TRACEPOINT
  fprintf(stderr, "BPF raw tracepoints unsupported\n");
  exit(1);
#else
  {
    union bpf_attr peattr;

    memset(&peattr, 0, sizeof(peattr));

    for (size_t i = 0; i < nprobes; ++i)
      {
	trace_data &t = raw_tracepoint_probes[i];
        peattr.raw_tracepoint.name = ((__u64)(unsigned long) (t.name.c_str()));
	peattr.raw_tracepoint.prog_fd = t.prog_fd;

        int fd = syscall(__NR_bpf, BPF_RAW_TRACEPOINT_OPEN, &peattr, sizeof(peattr));
        if (fd < 0)
	  {
	    fprintf(stderr, "Error opening probe raw tracepoint  %s: %s\n",
		    t.name.c_str(), strerror(errno));
	    goto fail;
	  }
        t.event_fd = fd;

      }
  }
  return;

 fail:
  unregister_raw_tracepoints(nprobes);
  exit(1);
#endif
}

static void
unregister_timers(const size_t nprobes)
{
  for (size_t i = 0; i < nprobes; ++i)
    close(timers[i].event_fd);
}

static void
register_timers()
{
  perf_event_attr peattr;

  memset(&peattr, 0, sizeof(peattr));
  peattr.size = sizeof(peattr);
  peattr.type = PERF_TYPE_SOFTWARE;
  peattr.config = PERF_COUNT_SW_CPU_CLOCK;

  for (size_t i = 0; i < timers.size(); ++i)
    {
      timer_data &t = timers[i];
      peattr.sample_period = t.period;

      int fd = perf_event_open(&peattr, -1, default_cpu, group_fd, 0);
      if (fd < 0)
        {
          int err = errno;
          unregister_timers(timers.size());
          fatal("Error opening timer probe id %zu: %s\n", i + 1, strerror(err));
        }

      t.event_fd = fd;
      if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, t.prog_fd) < 0)
        {
          int err = errno;
          unregister_timers(timers.size());
          fatal("Error installing bpf for timer probe id %zu: %s\n",
                i + 1, strerror(err));
        }
    }

  return;
}

static void
unregister_perf(const size_t nprobes)
{
  for (size_t i = 0; i < nprobes; ++i)
    close(perf_probes[i].event_fd);
}

static void
register_perf()
{
  for (size_t i = 0; i < perf_probes.size(); ++i)
    {
      perf_data &p = perf_probes[i];
      perf_event_attr peattr;

      memset(&peattr, 0, sizeof(peattr));
      peattr.size = sizeof(peattr);
      peattr.type = p.event_type;
      peattr.config = p.event_config;

      if (p.has_freq)
        {
          peattr.freq = 1;
          peattr.sample_freq = p.interval;
        }
      else
        peattr.sample_period = p.interval;

      // group_fd is not used since this event might have an
      // incompatible type/config.
      int fd = perf_event_open(&peattr, -1, default_cpu, -1, 0);
      if (fd < 0)
        {
          int err = errno;
          unregister_perf(perf_probes.size());
          fatal("Error opening perf probe id %zu: %s\n", i + 1, strerror(err));
        }

      p.event_fd = fd;
      if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, p.prog_fd) < 0)
        {
          int err = errno;
          unregister_perf(perf_probes.size());
          fatal("Error installing bpf for perf probe id %zu: %s\n",
                i + 1, strerror(err));
        }
    }
}

static void
init_internal_globals()
{
  using namespace bpf;

  int key = globals::EXIT;
  long val = 0;

  if (bpf_update_elem(map_fds[globals::internal_map_idx],
                     (void*)&key, (void*)&val, BPF_ANY) != 0)
    fatal("Error updating pid: %s\n", strerror(errno));

}

// PR22330: Initialize perf_event_map and perf_fds.
static void
init_perf_transport()
{
  using namespace bpf;

  unsigned ncpus = map_attrs[globals::perf_event_map_idx].max_entries;

  for (unsigned cpu = 0; cpu < ncpus; cpu++)
    {
      if (!cpu_online[cpu]) // -- skip inactive CPUs.
        {
          perf_fds.push_back(-1);
          transport_contexts.push_back(nullptr);
          continue;
        }

      struct perf_event_attr peattr;

      memset(&peattr, 0, sizeof(peattr));
      peattr.size = sizeof(peattr);
      peattr.sample_type = PERF_SAMPLE_RAW;
      peattr.type = PERF_TYPE_SOFTWARE;
      peattr.config = PERF_COUNT_SW_BPF_OUTPUT;
      peattr.sample_period = 1;
      peattr.wakeup_events = 1;

      int pmu_fd = perf_event_open(&peattr, -1/*pid*/, cpu, -1/*group_fd*/, 0);
      if (pmu_fd < 0)
        fatal("Error initializing perf event for cpu %d: %s\n", cpu, strerror(errno));
      if (bpf_update_elem(map_fds[globals::perf_event_map_idx],
                          (void*)&cpu, (void*)&pmu_fd, BPF_ANY) != 0)
        fatal("Error assigning perf event for cpu %d: %s\n", cpu, strerror(errno));
      ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
      perf_fds.push_back(pmu_fd);

      // Create a data structure to track what's happening on each CPU:
      bpf_transport_context *ctx
        = new bpf_transport_context(cpu, pmu_fd, ncpus, map_attrs, &map_fds,
                                    output_f, &interned_strings, &aggregates);
      transport_contexts.push_back(ctx);
    }

  // XXX: based on perf_event_mmap_header()
  // in kernel tools/testing/selftests/bpf/trace_helpers.c
  perf_event_page_size = getpagesize();
  perf_event_mmap_size = perf_event_page_size * (perf_event_page_count + 1);
  for (unsigned cpu = 0; cpu < ncpus; cpu++)
    {
      if (!cpu_online[cpu]) // -- skip inactive CPUs.
        {
          perf_headers.push_back(nullptr);
          continue;
        }

      int pmu_fd = perf_fds[cpu];
      void *base = mmap(NULL, perf_event_mmap_size,
                        PROT_READ | PROT_WRITE, MAP_SHARED,
                        pmu_fd, 0);
      if (base == MAP_FAILED)
        fatal("error mmapping header for perf_event fd %d\n", pmu_fd);
      perf_headers.push_back((perf_event_mmap_page*)base);
      if (log_level > 2)
        fprintf(stderr, "Initialized perf_event output on cpu %d\n", cpu);
    }
}

static void
load_bpf_file(const char *module)
{
  module_name = module;

  /* Extract basename: */
  char *buf = (char *)malloc(BPF_MAXSTRINGLEN * sizeof(char));
  string module_name_str(module);
  string module_basename_str
    = module_name_str.substr(module_name_str.rfind('/')+1); // basename
  size_t len = module_basename_str.copy(buf, BPF_MAXSTRINGLEN-1);
  buf[len] = '\0';
  module_basename = buf;

  int fd = open(module, O_RDONLY);
  if (fd < 0)
    fatal_sys();

  elf_version(EV_CURRENT);

  Elf *elf = elf_begin(fd, ELF_C_READ_MMAP_PRIVATE, NULL);
  if (elf == NULL)
    fatal_elf();
  module_elf = elf;

  Elf64_Ehdr *ehdr = elf64_getehdr(elf);
  if (ehdr == NULL)
    fatal_elf();

  /* Get username and set directory prefix: */
  user = getlogin(); 

  if (!user)
    fatal("an error occured while retrieving username. %s.\n", strerror(errno));

  // TODO: fix script_name so we can directly use it here 

  std::string module_name = std::string(module_basename);
  module_name = module_name.substr(0, module_name.size() - 3);

  prefix = "/var/tmp/systemtap-" + std::string(user) + "/" + module_name + "/";

  // Byte order should match the host, since we're loading locally.
  {
    const char *end_str;
    switch (ehdr->e_ident[EI_DATA])
      {
      case ELFDATA2MSB:
	if (__BYTE_ORDER == __BIG_ENDIAN)
	  break;
	end_str = "MSB";
	goto err_endian;
      case ELFDATA2LSB:
	if (__BYTE_ORDER == __LITTLE_ENDIAN)
	  break;
	end_str = "LSB";
	goto err_endian;
      case ELFCLASSNONE:
	end_str = "none";
	goto err_endian;
      default:
	end_str = "unknown";
      err_endian:
	fatal("incorrect byte ordering: %s\n", end_str);
      }
  }

  // Tiny bit of sanity checking on the rest of the header.  Since LLVM
  // began by producing files with EM_NONE, accept that too.
  if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF)
    fatal("incorrect machine type: %d\n", ehdr->e_machine);

  unsigned shnum = ehdr->e_shnum;
  prog_fds.assign(shnum, -1);

  std::vector<Elf64_Shdr *> shdrs(shnum, NULL);
  std::vector<Elf_Data *> sh_data(shnum, NULL);
  std::vector<const char *> sh_name(shnum, NULL);
  unsigned maps_idx = 0;
  unsigned version_idx = 0;
  unsigned license_idx = 0;
  unsigned script_name_idx = 0;
  unsigned interned_strings_idx = 0;
  unsigned aggregates_idx = 0;
  unsigned kprobes_idx = 0;
  unsigned begin_idx = 0;
  unsigned end_idx = 0;

  std::vector<unsigned> procfsprobes_idx;

  // First pass to identify special sections, and make sure
  // all data is readable.
  for (unsigned i = 1; i < shnum; ++i)
    {
      Elf_Scn *scn = elf_getscn(elf, i);
      if (!scn)
	fatal_elf();

      Elf64_Shdr *shdr = elf64_getshdr(scn);
      if (!shdr)
	fatal_elf();

      const char *shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
      if (!shname)
	fatal_elf();

      // We need not consider any empty sections.
      if (shdr->sh_size == 0 || !*shname)
	continue;

      Elf_Data *data = elf_getdata(scn, NULL);
      if (data == NULL)
	fatal_elf();

      shdrs[i] = shdr;
      sh_name[i] = shname;
      sh_data[i] = data;

      if (strcmp(shname, "license") == 0)
	license_idx = i;
      else if (strcmp(shname, "stapbpf_script_name") == 0)
	script_name_idx = i;
      else if (strcmp(shname, "stapbpf_interned_strings") == 0)
        interned_strings_idx = i;
      else if (strcmp(shname, "stapbpf_aggregates") == 0)
        aggregates_idx = i;
      else if (strcmp(shname, "version") == 0)
	version_idx = i;
      else if (strcmp(shname, "maps") == 0)
	maps_idx = i;
      else if (strcmp(shname, "kprobes") == 0)
	kprobes_idx = i;
      else if (strcmp(shname, "stap_begin") == 0)
	begin_idx = i;
      else if (strcmp(shname, "stap_end") == 0)
	end_idx = i;
      else if (strncmp(shname, "procfs", strlen("procfs")) == 0) {
        // procfs probes have a "procfs" prefix in their names, we don't
        // use normal strcmp as the full shname includes args
        procfsprobes_idx.push_back(i);
      }
    }

  // Two special sections are not optional.
  if (license_idx != 0)
    module_license = static_cast<char *>(sh_data[license_idx]->d_buf);
  else
    fatal("missing license section\n");
  if (script_name_idx != 0)
    script_name = static_cast<char *>(sh_data[script_name_idx]->d_buf);
  else
    script_name = "<unknown>";

  if (version_idx != 0)
    {
      unsigned long long size = shdrs[version_idx]->sh_size;
      if (size != 4)
	fatal("invalid version size (%llu)\n", size);
      memcpy(&kernel_version, sh_data[version_idx]->d_buf, 4);
    }
  else
    fatal("missing version section\n");

  // Create bpf maps as required.
  if (maps_idx != 0)
    instantiate_maps(shdrs[maps_idx], sh_data[maps_idx]);

  // Create interned strings as required.
  if (interned_strings_idx != 0)
    {
      // XXX: Whatever the type used by the translator, this section
      // just holds a blob of NUL-terminated strings we parse as follows:
      char *strtab = static_cast<char *>(sh_data[interned_strings_idx]->d_buf);
      unsigned long long strtab_size = shdrs[interned_strings_idx]->sh_size;
      unsigned ofs = 0;
      bool found_hdr = false;
      while (ofs < strtab_size)
        {
          // XXX: Potentially vulnerable to NUL byte in string constant.
          std::string str(strtab+ofs); // XXX: will slurp up to NUL byte
          if (str.size() == 0 && !found_hdr)
            found_hdr = true; // section *may* start with an extra NUL byte
          else
            interned_strings.push_back(str);
          ofs += str.size() + 1;
        }
    }

  // PR23476: Initialize table of statistical aggregates.
  if (aggregates_idx != 0)
    {
      uint64_t *aggtab = static_cast<uint64_t *>(sh_data[aggregates_idx]->d_buf);
      unsigned long long aggtab_size = shdrs[aggregates_idx]->sh_size;
      unsigned ofs = 0; unsigned i = 0;
      while (ofs < aggtab_size)
        {
          bpf::globals::agg_idx agg_id = (bpf::globals::agg_idx)aggtab[i];
          bpf::globals::interned_stats_map ism;
          for (unsigned j = 0; j < bpf::globals::stat_fields.size(); j++)
            {
              ism.push_back(aggtab[i+1+j]);
            }
          aggregates[agg_id] = bpf::globals::deintern_stats_map(ism);
          i += 1 + bpf::globals::stat_fields.size();
          ofs = sizeof(uint64_t) * i;
        }
    }

  // Relocate all programs that require it.
  for (unsigned i = 1; i < shnum; ++i)
    {
      Elf64_Shdr *rel_hdr = shdrs[i];
      if (rel_hdr == NULL || rel_hdr->sh_type != SHT_REL)
	continue;

      unsigned progi = rel_hdr->sh_info;
      if (progi == 0 || progi >= shnum)
	fatal("invalid section info %u->%u\n", i, progi);
      Elf64_Shdr *prog_hdr = shdrs[progi];

      unsigned symi = rel_hdr->sh_link;
      if (symi == 0 || symi >= shnum)
	fatal("invalid section link %u->%u\n", i, symi);
      Elf64_Shdr *sym_hdr = shdrs[symi];

      unsigned stri = sym_hdr->sh_link;
      if (stri == 0 || stri >= shnum)
	fatal("invalid section link %u->%u\n", symi, stri);

      if (prog_hdr->sh_flags & SHF_EXECINSTR)
	prog_relocate(sh_data[progi], sh_data[i], sh_data[symi],
		      sh_data[stri], sh_name[progi], maps_idx,
		      prog_hdr->sh_flags & SHF_ALLOC);
    }

  // Load all programs that require it.
  for (unsigned i = 1; i < shnum; ++i)
    {
      Elf64_Shdr *shdr = shdrs[i];
      if ((shdr->sh_flags & SHF_ALLOC) && (shdr->sh_flags & SHF_EXECINSTR))
	prog_fds[i] = prog_load(sh_data[i], sh_name[i]);
    }

  // Remember begin, end and procfs-like probes.
  if (begin_idx)
    {
      Elf64_Shdr *shdr = shdrs[begin_idx];
      if (shdr->sh_flags & SHF_EXECINSTR)
	prog_begin = sh_data[begin_idx];
    }
  if (end_idx)
    {
      Elf64_Shdr *shdr = shdrs[end_idx];
      if (shdr->sh_flags & SHF_EXECINSTR)
	prog_end = sh_data[end_idx];
    }

  for (unsigned i = 0; i < procfsprobes_idx.size(); ++i)
   {
     unsigned actual_idx = procfsprobes_idx[i];

     Elf64_Shdr *shdr = shdrs[actual_idx];
     if (shdr->sh_flags & SHF_EXECINSTR)   
       collect_procfsprobe(sh_name[actual_idx], sh_data[actual_idx]);
   }

  // Record all kprobes.
  if (kprobes_idx != 0)
    {
      // The Preferred Systemtap Way puts kprobe strings into a symbol
      // table, so that multiple kprobes can reference the same program.

      // ??? We don't really have to have a separate kprobe symbol table;
      // we could pull kprobes out of the main symbol table too.  This
      // would probably make it easier for llvm-bpf folks to transition.
      // One would only need to create symbol aliases with custom asm names.

      Elf64_Shdr *sym_hdr = shdrs[kprobes_idx];
      if (sym_hdr->sh_type != SHT_SYMTAB)
	fatal("invalid section type for kprobes section\n");

      unsigned stri = sym_hdr->sh_link;
      if (stri == 0 || stri >= shnum)
	fatal("invalid section link %u->%u\n", kprobes_idx, stri);

      kprobe_collect_from_syms(sh_data[kprobes_idx], sh_data[stri]);
    }
  else
    {
      // The original llvm-bpf way puts kprobe strings into the
      // section name.  Each kprobe has its own program.
      for (unsigned i = 1; i < shnum; ++i)
	maybe_collect_kprobe(sh_name[i], i, i, 0);
    }

  // Record all other probes
  for (unsigned i = 1; i < shnum; ++i) {
    if (strncmp(sh_name[i], "uprobe", 6) == 0)
      collect_uprobe(sh_name[i], i, i);
    if (strncmp(sh_name[i], "trace", 5) == 0)
      collect_tracepoint(sh_name[i], i, i);
    if (strncmp(sh_name[i], "raw_trace", 9) == 0)
      collect_raw_tracepoint(sh_name[i], i, i);
    if (strncmp(sh_name[i], "perf", 4) == 0)
      collect_perf(sh_name[i], i, i);
    if (strncmp(sh_name[i], "timer", 5) == 0)
      collect_timer(sh_name[i], i, i);
  }
}

static int
get_exit_status()
{
  int key = bpf::globals::EXIT;
  long val = 0;

  if (bpf_lookup_elem
       (map_fds[bpf::globals::internal_map_idx], &key, &val) != 0)
    fatal("error during bpf map lookup: %s\n", strerror(errno));

  return val;
}

// XXX: based on perf_event_sample
// in kernel tools/testing/selftests/bpf/trace_helpers.c
struct perf_event_sample {
  struct perf_event_header header;
  __u32 size;
  char data[];
};

static enum bpf_perf_event_ret
perf_event_handle(struct perf_event_header *hdr, void *private_data)
{
  // XXX: based on bpf_perf_event_print
  // in kernel tools/testing/selftests/bpf/trace_helpers.c

  struct perf_event_sample *e = (struct perf_event_sample *)hdr;
  bpf_transport_context *ctx = (bpf_transport_context *)private_data;
  bpf_perf_event_ret ret;

  // Make sure we weren't passed a userspace context by accident.
  assert(ctx->pmu_fd >= 0);

  if (e->header.type == PERF_RECORD_SAMPLE)
    {
      __u32 actual_size = e->size - sizeof(e->size);
      ret = bpf_handle_transport_msg(e->data, actual_size, ctx);
      if (ret != LIBBPF_PERF_EVENT_CONT)
        return ret;
    }
  else if (e->header.type == PERF_RECORD_LOST)
    {
      struct lost_events {
        struct perf_event_header header;
        __u64 id;
        __u64 lost;
      };
      struct lost_events *lost = (lost_events *) e;
      fprintf(stderr, "WARNING: lost %lld perf_events on cpu %d\n",
              (long long)lost->lost, ctx->cpu);
    }
  else
    {
      fprintf(stderr, "WARNING: unknown perf_event type=%d size=%d on cpu %d\n",
              e->header.type, e->header.size, ctx->cpu);
    }
  return LIBBPF_PERF_EVENT_CONT;
}

// PR22330: Listen for perf_events.
static void
perf_event_loop(pthread_t main_thread)
{
  // XXX: based on perf_event_poller_multi()
  // in kernel tools/testing/selftests/bpf/trace_helpers.c

  enum bpf_perf_event_ret ret;
  void *data = NULL;
  size_t len = 0;

  unsigned ncpus
    = map_attrs[bpf::globals::perf_event_map_idx].max_entries;
  unsigned n_active_cpus
    = count_active_cpus();
  struct pollfd *pmu_fds
    = (struct pollfd *)malloc(n_active_cpus * sizeof(struct pollfd));
  vector<unsigned> cpuids;

  assert(ncpus == perf_fds.size());
  unsigned i = 0;
  for (unsigned cpu = 0; cpu < ncpus; cpu++)
    {
      if (!cpu_online[cpu]) continue; // -- skip inactive CPUs.

      pmu_fds[i].fd = perf_fds[cpu];
      pmu_fds[i].events = POLLIN;
      cpuids.push_back(cpu);
      i++;
    }
  assert(n_active_cpus == cpuids.size());

  // Avoid multiple warnings about errors reading from an fd:
  std::set<int> already_warned;

  for (;;)
    {
      if (log_level > 3)
        fprintf(stderr, "Polling for perf_event data on %d cpus...\n", n_active_cpus);
      int ready = poll(pmu_fds, n_active_cpus, 1000); // XXX: Consider setting timeout -1 (unlimited).
      if (ready < 0 && errno == EINTR)
        goto signal_exit;
      if (ready < 0)
        fatal("Error checking for perf events: %s\n", strerror(errno));
      for (unsigned i = 0; i < n_active_cpus; i++)
        {
          if (pmu_fds[i].revents <= 0)
            continue;
          if (log_level > 3)
            fprintf(stderr, "Saw perf_event on fd %d\n", pmu_fds[i].fd);

          ready --;
          unsigned cpu = cpuids[i];
          ret = bpf_perf_event_read_simple
            (perf_headers[cpu],
             perf_event_page_count * perf_event_page_size,
             perf_event_page_size,
             &data, &len,
             perf_event_handle, transport_contexts[cpu]);

          if (ret == LIBBPF_PERF_EVENT_DONE)
            {
              // Saw STP_EXIT message. If the exit flag is set,
              // wake up main thread to begin program shutdown.
              if (get_exit_status())
                  goto signal_exit;
              continue;
            }
          if (ret != LIBBPF_PERF_EVENT_CONT)
            if (already_warned.count(pmu_fds[i].fd) == 0)
              {
                fprintf(stderr, "WARNING: could not read from perf_event buffer on fd %d\n", pmu_fds[i].fd);
                already_warned.insert(pmu_fds[i].fd);
              }
        }
      assert(ready == 0);
    }

 signal_exit:
  pthread_kill(main_thread, SIGINT);
  free(pmu_fds);
  return;
}


static void
procfs_read_event_loop (procfsprobe_data* data, bpf_transport_context* uctx)
{
  std::string path_s = prefix + data->path;
  const char* path = path_s.c_str();

  Elf_Data* prog = data->read_prog;  

  while (true) 
    {
      int fd = open(path, O_WRONLY);

      if (fd == -1)
        {
          if (errno == ENOENT)
            fatal("an error occured while opening procfs fifo (%s). %s.\n", path, strerror(errno));
          
          fprintf(stderr, "WARNING: an error occurred while opening procfs fifo (%s). %s.\n", 
                  path, strerror(errno));
          continue;
        }
 
      procfs_lock.lock();

      // Run the probe and collect the message.
      bpf_interpret(prog->d_size / sizeof(bpf_insn), static_cast<bpf_insn *>(prog->d_buf), uctx);

      // Make a copy of the message.
      std::string msg = uctx->procfs_msg;

      procfs_lock.unlock();

      if (data->maxsize_val && (msg.size() > data->maxsize_val - 1))
          fprintf(stderr, "WARNING: procfs message size (%ld) exceeds specified maximum size (%ld).\n", 
                  msg.size() + 1, data->maxsize_val);

      if (write(fd, msg.c_str(), msg.size() + 1) == -1)
        {
          fprintf(stderr, "WARNING: an error occurred while writing to procfs fifo (%s). %s.\n", 
                  path, strerror(errno));
          (void) close(fd);
          continue;
        }

      (void) close(fd);

      // We're not sure at this point whether the read end of the pipe has closed. We 
      // perform a small open hack to spin until read end of the pipe has closed.     

      do {

        fd = open(path, O_WRONLY | O_NONBLOCK);

        if (fd != -1) close(fd);

      } while (fd != -1);
    }
}


static void
procfs_write_event_loop (procfsprobe_data* data, bpf_transport_context* uctx)
{
  std::string path_s = prefix + data->path;
  const char* path = path_s.c_str();

  std::vector<Elf_Data*> prog = data->write_prog;

  while (true) 
    {
      int fd = open(path, O_RDONLY);

      if (fd == -1)
        {
          if (errno == ENOENT)
            fatal("an error occured while opening procfs fifo (%s). %s.\n", path, strerror(errno));
          
          fprintf(stderr, "WARNING: an error occurred while opening procfs fifo (%s). %s.\n", 
                  path, strerror(errno));
          continue;
        }
 
      std::string msg;

      unsigned read_size = 1024;
      int bytes_read;

      do {

        char buffer_feed[read_size];
        bytes_read = read(fd, buffer_feed, read_size);

        if (bytes_read == -1)
          fprintf(stderr, "WARNING: an error occurred while reading from procfs fifo (%s). %s.\n", 
                    path, strerror(errno));

        if (bytes_read > 0)
          msg.append(std::string(buffer_feed));

      } while (bytes_read > 0);

      (void) close(fd);

      procfs_lock.lock();

      uctx->procfs_msg = msg;

      // Now that we have the message, run the probes serially.
      for (unsigned i = 0; i < prog.size(); ++i) 
        bpf_interpret(prog[i]->d_size / sizeof(bpf_insn), static_cast<bpf_insn *>(prog[i]->d_buf), uctx);   
    
      procfs_lock.unlock();
    } 
}


static void
procfs_cleanup()
{
  // Delete files and directories created for procfs-like probes.
  for (size_t k = 0; k < procfsprobes.size(); ++k)
    {
      std::string file_s = prefix + procfsprobes[k].path;
      const char* file = file_s.c_str();
      if (remove_file_or_dir(file))
        fprintf(stderr, "WARNING: an error occurred while deleting a file (%s). %s.\n", file, strerror(errno));
    }

  const char* dir = prefix.c_str();
  if (procfsprobes.size() > 0 && remove_file_or_dir(dir))
    fprintf(stderr, "WARNING: an error ocurred while deleting a directory (%s). %s.\n", dir, strerror(errno));
}


static void
procfs_spawn(bpf_transport_context* uctx)
{
  // Enable cleanup routine.
  if (atexit(procfs_cleanup))
    fatal("an error occurred while setting up procfs cleaner. %s.\n", strerror(errno));

  // Create directory for procfs-like probes.
  if (procfsprobes.size() > 0 && create_dir(prefix.c_str()))
    fatal("an error occurred while making procfs directory. %s.\n", strerror(errno)); 
  
  // Create all of the fifos used for procfs-like probes and spawn threads.
  for (size_t k =0; k < procfsprobes.size(); ++k)
    {
      procfsprobe_data* data = &procfsprobes[k];

      std::string path = prefix + data->path;

      uint64_t cmask = umask(data->umask);

      mode_t mode = (data->type == 'r') ? 0444 : 0222;

      if ((mkfifo(path.c_str(), mode) == -1))
        fatal("an error occured while making procfs fifos. %s.\n", strerror(errno));

      // TODO: Could set the owner/group of the fifo to the effective user.

      umask(cmask);

      if (data->type == 'r')
        std::thread(procfs_read_event_loop, data, uctx).detach();    
      else      
        std::thread(procfs_write_event_loop, data, uctx).detach(); 
    }
}


static void
usage(const char *argv0)
{
  printf("Usage: %s [-v][-w][-V][-h] [-o FILE] <bpf-file>\n"
	 "  -h, --help       Show this help text\n"
	 "  -v, --verbose    Increase verbosity\n"
	 "  -V, --version    Show version\n"
	 "  -w               Suppress warnings\n"
	 "  -x pid           Sets the '_stp_target' variable to pid.\n"
	 "  -o FILE          Send output to FILE\n",
	 argv0);
}


void
sigint(int s)
{
  // suppress any subsequent SIGINTs that may come from stap parent process
  signal(s, SIG_IGN);

  // during the exit phase, ^C should exit immediately
  if (exit_phase)
    {
      if (!interrupt_message) // avoid duplicate message
        fprintf(stderr, "received interrupt during exit probe\n");
      interrupt_message = 1;
      abort();
    }

  // set exit flag
  int key = bpf::globals::EXIT;
  long val = 1;

  if (bpf_update_elem
       (map_fds[bpf::globals::internal_map_idx], &key, &val, 0) != 0)
     fatal("error during bpf map update: %s\n", strerror(errno));
}

int
main(int argc, char **argv)
{
  static const option long_opts[] = {
    { "help", 0, NULL, 'h' },
    { "verbose", 0, NULL, 'v' },
    { "version", 0, NULL, 'V' },
  };

  int rc;

  while ((rc = getopt_long(argc, argv, "hvVwx:o:", long_opts, NULL)) >= 0)
    switch (rc)
      {
      case 'v':
        log_level++;
        break;
      case 'w':
        warnings = 0;
        break;

      case 'x':
	target_pid = atoi(optarg);
	break;

      case 'o':
	output_f = fopen(optarg, "w");
	if (output_f == NULL)
	  {
	    fprintf(stderr, "Error opening %s for output: %s\n",
		    optarg, strerror(errno));
	    return 1;
	  }
	break;

      case 'V':
        printf("Systemtap BPF loader/runner (version %s, %s)\n"
	       "Copyright (C) 2016-2019 Red Hat, Inc. and others\n" // PRERELEASE
               "This is free software; "
	       "see the source for copying conditions.\n",
	       VERSION, STAP_EXTENDED_VERSION);
	return 0;

      case 'h':
	usage(argv[0]);
	return 0;

      default:
      do_usage:
	usage(argv[0]);
	return 1;
      }
  if (optind != argc - 1)
    goto do_usage;

  // Be sure dmesg mentions that we are loading bpf programs:
  kmsg = fopen("/dev/kmsg", "w");
  if (kmsg == NULL)
    fprintf(stderr, "WARNING: could not open /dev/kmsg for diagnostics: %s\n", strerror(errno));

  load_bpf_file(argv[optind]); // <- XXX initializes cpus online, PR24543 initializes default_cpu
  init_internal_globals();
  init_perf_transport();

  // Create a bpf_transport_context for userspace programs:
  unsigned ncpus = map_attrs[bpf::globals::perf_event_map_idx].max_entries;
  bpf_transport_context uctx(default_cpu, -1/*pmu_fd*/, ncpus,
                             map_attrs, &map_fds, output_f,
                             &interned_strings, &aggregates);

  if (create_group_fds() < 0)
    fatal("Error creating perf event group: %s\n", strerror(errno));

  register_kprobes();
  register_uprobes();
  register_timers();
  register_tracepoints();
  register_raw_tracepoints();
  register_perf();

  // Run the begin probes.
  if (prog_begin)
    bpf_interpret(prog_begin->d_size / sizeof(bpf_insn),
                  static_cast<bpf_insn *>(prog_begin->d_buf),
                  &uctx);

  // Wait for ^C; read BPF_OUTPUT events, copying them to output_f.
  signal(SIGINT, (sighandler_t)sigint);
  signal(SIGTERM, (sighandler_t)sigint);

  // PR22330: Listen for perf_events:
  std::thread(perf_event_loop, pthread_self()).detach();

  // Spawn all procfs threads.
  procfs_spawn(&uctx);

  // Now that the begin probe has run and the perf_event listener is active, enable the kprobes.
  ioctl(group_fd, PERF_EVENT_IOC_ENABLE, 0);

  // Wait for STP_EXIT message:
  while (!get_exit_status())
    pause();

  // Disable the kprobes before deregistering and running exit probes.
  ioctl(group_fd, PERF_EVENT_IOC_DISABLE, 0);
  close(group_fd);

  // Unregister all probes.
  unregister_kprobes(kprobes.size());
  unregister_uprobes(uprobes.size());
  unregister_timers(timers.size());
  unregister_perf(perf_probes.size());
  unregister_tracepoints(tracepoint_probes.size());
  unregister_raw_tracepoints(raw_tracepoint_probes.size());

  // Clean procfs-like probe files.
  procfs_cleanup();

  // We are now running exit probes, so ^C should exit immediately:
  exit_phase = 1;
  signal(SIGINT, (sighandler_t)sigint); // restore previously ignored signal
  signal(SIGTERM, (sighandler_t)sigint);

  // Run the end+error probes.
  if (prog_end)
    bpf_interpret(prog_end->d_size / sizeof(bpf_insn),
                  static_cast<bpf_insn *>(prog_end->d_buf),
                  &uctx);

  // Clean up transport layer allocations:
  for (std::vector<bpf_transport_context *>::iterator it = transport_contexts.begin();
       it != transport_contexts.end(); it++)
    delete *it;

  elf_end(module_elf);
  fclose(kmsg);
  return 0;
}
