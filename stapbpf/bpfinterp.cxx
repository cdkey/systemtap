/* bpfinterp.c - SystemTap BPF interpreter
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
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <inttypes.h>
#include <map>
#include "bpfinterp.h"
#include "libbpf.h"
#include "../bpf-internal.h"

inline uintptr_t
as_int(void *ptr)
{
  return reinterpret_cast<uintptr_t>(ptr);
}

inline uintptr_t
as_int(uint64_t *ptr)
{
  return reinterpret_cast<uintptr_t>(ptr);
}

inline void *
as_ptr(uintptr_t ptr)
{
  return reinterpret_cast<void *>(ptr);
}

inline void *
as_ptr(uint64_t *ptr)
{
  return reinterpret_cast<void *>(ptr);
}

inline void *
as_ptr(char *ptr)
{
  return reinterpret_cast<void *>(ptr);
}

inline char *
as_str(uintptr_t ptr)
{
  return reinterpret_cast<char *>(ptr);
}

const std::string
remove_tag(const char *fstr)
{
  while (*(++fstr) != '>' && *fstr != '\0');
  if (*fstr == '\0') return ""; // avoid segfault
  ++fstr;
  const char *end = fstr + strlen(fstr);
  while (*(--end) != '<' && end >= fstr);
  assert(end >= fstr);
  return std::string(fstr, end - fstr);
}

// Used with map_get_next_key for int keys. Uses signed type so that
// negative values are properly sorted.
typedef std::vector<std::set<int64_t>> map_int_keys;

// Used with map_get_next_key for string keys.
typedef std::vector<std::set<std::string>> map_str_keys;

struct map_keys {
  map_int_keys int_keys;
  map_str_keys str_keys;
};

// Wrapper for bpf_get_next_key that includes logic for accessing
// keys in ascending or descending order.
int
map_get_next_key(int fd_idx, int64_t key, int64_t next_key,
                 int sort_direction, int64_t limit,
                 bpf_transport_context *ctx, map_keys &keys)
{
  int fd = (*ctx->map_fds)[fd_idx];

  // XXX: May want to pass the actual key type. For now just guess:
  bool is_str = ctx->map_attrs[fd_idx].key_size == BPF_MAXSTRINGLEN;

  // Final iteration, therefore keys.back() is no longer needed:
  if (limit == 0)
    goto empty;

  if (!sort_direction)
    return bpf_get_next_key(fd, as_ptr(key), as_ptr(next_key));

  // Beginning of iteration; populate a new set of keys for
  // the map specified by fd. Multiple sets can be associated
  // with a single map during execution of nested foreach loops.
  if (!key && is_str)
    {
      // XXX: BPF_MAXSTRINGLEN+1 to avoid coverity warning
      char k[BPF_MAXSTRINGLEN_PLUS], n[BPF_MAXSTRINGLEN_PLUS];
      std::set<std::string> s;

      int rc = bpf_get_next_key(fd, 0, as_ptr(n));
      while (!rc)
        {
          strncpy(k, n, BPF_MAXSTRINGLEN);
          s.insert(std::string(k));
          rc = bpf_get_next_key(fd, as_ptr(k), as_ptr(n));
        }

      if (s.empty())
        return -1;

      keys.str_keys.push_back(s);
    }
  else if (!key) // && !is_str
    {
      uint64_t k, n;
      std::set<int64_t> s;

      int rc = bpf_get_next_key(fd, 0, as_ptr(&n));
      while (!rc)
        {
          s.insert(n);
          k = n;
          rc = bpf_get_next_key(fd, as_ptr(&k), as_ptr(&n));
        }

      if (s.empty())
        return -1;

      keys.int_keys.push_back(s);
    }

  if (is_str)
    {
      std::set<std::string> &s = keys.str_keys.back();
      char *nstr = reinterpret_cast<char *>(next_key);
      std::string skey;

      if (sort_direction > 0)
        {
          auto it = s.begin();
          if (it == s.end())
            goto empty;
          skey = *it;
          strncpy(nstr, skey.c_str(), BPF_MAXSTRINGLEN);
        }
      else
        {
          auto it = s.rbegin();
          if (it == s.rend())
            goto empty;
          skey = *it;
          strncpy(nstr, skey.c_str(), BPF_MAXSTRINGLEN);
        }

      s.erase(skey);
    }
  else // if (!is_str)
    {
      std::set<int64_t> &s = keys.int_keys.back();
      uint64_t *nptr = reinterpret_cast<uint64_t *>(next_key);

      if (sort_direction > 0)
        {
          auto it = s.begin();
          if (it == s.end())
            goto empty;
          *nptr = *it;
        }
      else
        {
          auto it = s.rbegin();
          if (it == s.rend())
            goto empty;
          *nptr = *it;
        }

      s.erase(*nptr);
    }
  return 0;

empty:
  if (is_str)
    keys.str_keys.pop_back();
  else // if (!is_str)
    keys.int_keys.pop_back();
  return -1;
}

// TODO: Adapt to MAXPRINTFARGS == 32.
uint64_t
bpf_sprintf(std::vector<std::string> &strings, char *fstr,
            uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
  char s[256]; // TODO: configure maximum length setting e.g. BPF_MAXSPRINTFLEN
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  snprintf(s, 256, fstr, arg1, arg2, arg3);
#pragma GCC diagnostic pop
  std::string str(s, 256);
  strings.push_back(str);

  // Elements of "strings" should not be mutated to avoid
  // invalidating c_str() pointers.
  return reinterpret_cast<uint64_t>(strings.back().c_str());
}

// Allocates and returns a buffer of percpu data for a stat field:
uint64_t *
stapbpf_stat_get_percpu(bpf::globals::map_idx map, uint64_t idx,
                        bpf_transport_context *ctx)
{
  uint64_t *ret = (uint64_t *)calloc(ctx->ncpus, sizeof(uint64_t));
  int res = bpf_lookup_elem((*ctx->map_fds)[map], as_ptr(idx), ret);
  if (res)
    // element could not be found
    return 0;
  else
    return ret;
}

// XXX Based on _stp_stat_get in runtime/stat.c.
// There might be a clever way to avoid code duplication later,
// but right now the code format is too different. Just reimplement.
uint64_t
stapbpf_stat_get(bpf::globals::agg_idx agg_id, uint64_t idx,
                 stat_component_type sc_op,
                 bpf_transport_context *ctx)
{
  if (ctx->aggregates->find(agg_id) == ctx->aggregates->end())
    // aggregate could not be found
    abort();
  bpf::globals::stats_map sd = (*ctx->aggregates)[agg_id];

  // XXX Based on struct stat_data in runtime/stat.h:
  struct stapbpf_stat_data {
    int shift;
    int64_t count;
    int64_t sum;
    int64_t avg_s;
    // TODO PR23476: Add more fields.
  } agg;
  // TODO: Consider caching each agg for the duration of userspace program execution.

  // Retrieve the fields that we are going to aggregate.
  //
  // XXX: This took a while to figure out.
  // bpf_map_lookup_elem() for percpu map returns an array.
  uint64_t *count_data = stapbpf_stat_get_percpu(sd["count"], idx, ctx);
  uint64_t *sum_data = stapbpf_stat_get_percpu(sd["sum"], idx, ctx);

  // TODO PR23476: Simplified code for now.
  agg.shift = 0;
  agg.count = 0;
  agg.sum = 0;
  for (unsigned i = 0; i < ctx->ncpus; i++) // XXX for_each_possible_cpu(i)
  {
    agg.count += count_data[i];
    agg.sum += sum_data[i];
  }

  free(count_data);
  free(sum_data);

  // XXX Simplified version of _stp_div64():
  if (agg.count == 0)
    agg.avg_s = 0;
  else
    agg.avg_s = (agg.sum << agg.shift) / agg.count;

  switch (sc_op)
    {
    case sc_average:
      if (agg.count == 0)
        abort(); // TODO: Should produce 'empty aggregate' error.
      return agg.avg_s;

    case sc_count:
      return agg.count;

    case sc_sum:
      return agg.sum;

    case sc_none:
      assert(0); // should not happen, as sc_none is only used in foreach slots

    // TODO PR23476: Not yet implemented.
    case sc_min:
    case sc_max:
    case sc_variance:
    default:
      abort();
    }
}

uint64_t
bpf_ktime_get_ns()
{
  struct timespec t;
  clock_gettime (CLOCK_BOOTTIME, &t);
  return (t.tv_sec * 1000000000) + t.tv_nsec;
}


enum bpf_perf_event_ret
bpf_handle_transport_msg(void *buf, size_t size,
                         bpf_transport_context *ctx)
{
  // Unpack transport message:
  struct bpf_transport_msg {
    BPF_TRANSPORT_VAL type;
    BPF_TRANSPORT_ARG content_start;
  };
  bpf_transport_msg *_msg = (bpf_transport_msg *) buf;
  bpf::globals::perf_event_type msg_type = (bpf::globals::perf_event_type)_msg->type;
  void *msg_content = (void*)&_msg->content_start;
  size_t msg_size = size - sizeof(BPF_TRANSPORT_ARG);

  // Used for bpf::globals::STP_EXIT:
  int exit_key = bpf::globals::EXIT;
  long exit_val = 1;

  // Used for bpf::globals::STP_FORMAT_ARG:
  void *arg;

  switch (msg_type)
    {
    case bpf::globals::STP_EXIT:
      // Signal an exit from the program:
      if (bpf_update_elem((*ctx->map_fds)[bpf::globals::internal_map_idx],
                          &exit_key, &exit_val, BPF_ANY) != 0)
        abort(); // could not set exit status
      return LIBBPF_PERF_EVENT_DONE;

    case bpf::globals::STP_PRINTF_START:
      if (ctx->in_printf)
        abort(); // printf already started
      if (msg_size != sizeof(BPF_TRANSPORT_ARG))
        abort(); // wrong argument size
      ctx->in_printf = true; ctx->format_no = -1;
      ctx->expected_args = *(BPF_TRANSPORT_ARG*)msg_content;
      break;

    case bpf::globals::STP_PRINTF_END:
      if (!ctx->in_printf)
        abort(); // printf not started
      if (ctx->format_no < 0 || ctx->format_no >= (int)ctx->interned_strings->size())
        abort(); // printf format is missing
      if (ctx->printf_args.size() != ctx->expected_args)
        abort(); // wrong number of args

      // TODO: Check this code on 32-bit systems after fixing PR24358.
      //
      // XXX: Surprisingly, it is not easy to pass an array to a
      // printf-type function. The best I can do for now is hardcode a
      // call to fprintf with BPF_MAXPRINTFARGS arguments:
      {
      std::string &format_str = (*ctx->interned_strings)[ctx->format_no];
      void *fargs[BPF_MAXPRINTFARGS];
      for (unsigned i = 0; i < BPF_MAXPRINTFARGS; i++)
        if (i < ctx->printf_args.size()
            && ctx->printf_arg_types[i] == bpf::globals::STP_PRINTF_ARG_LONG)
          fargs[i] = (void *)*(uint64_t*)ctx->printf_args[i];
        else if (i < ctx->printf_args.size())
          fargs[i] = ctx->printf_args[i];
        else
          fargs[i] = NULL;
      assert(BPF_MAXPRINTFARGS == 32); // XXX: Change the fprintf() call if this changes.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
      fprintf(ctx->output_f, format_str.c_str(),
              fargs[0], fargs[1], fargs[2], fargs[3], fargs[4], fargs[5], fargs[6], fargs[7],
              fargs[8], fargs[9], fargs[10], fargs[11], fargs[12], fargs[13], fargs[14], fargs[15],
              fargs[16], fargs[17], fargs[18], fargs[19], fargs[20], fargs[21], fargs[22], fargs[23],
              fargs[24], fargs[25], fargs[26], fargs[27], fargs[28], fargs[29], fargs[30], fargs[31]);
      fflush(ctx->output_f);
#pragma GCC diagnostic pop
      }

      // Deallocate accumulated format+args:
      ctx->in_printf = false; ctx->format_no = -1;
      for (unsigned i = 0; i < ctx->printf_args.size(); i++)
        free(ctx->printf_args[i]);
      ctx->printf_args.clear();
      ctx->printf_arg_types.clear();
      break;

    case bpf::globals::STP_PRINTF_FORMAT:
      if (!ctx->in_printf)
        abort(); // printf not started
      if (ctx->format_no != -1)
        abort(); // printf already has format
      if (msg_size != sizeof(BPF_TRANSPORT_ARG))
        abort(); // wrong argument size
      ctx->format_no = *(BPF_TRANSPORT_ARG*)msg_content;
      break;

    // XXX: Could save spurious mallocs by storing ARG_LONG as the void * itself.
    case bpf::globals::STP_PRINTF_ARG_LONG:
    case bpf::globals::STP_PRINTF_ARG_STR:
      if (!ctx->in_printf)
        abort(); // printf not started
      arg = malloc(msg_size);
      memcpy(arg, msg_content, msg_size);
      ctx->printf_args.push_back(arg);
      ctx->printf_arg_types.push_back(msg_type);
      break;

    default:
      abort();
    } 
  return LIBBPF_PERF_EVENT_CONT;
}

uint64_t
bpf_interpret(size_t ninsns, const struct bpf_insn insns[],
              bpf_transport_context *ctx)
{
  uint64_t result = 0; // return value
  uint64_t stack[512 / 8];
  uint64_t regs[MAX_BPF_REG];
  memset(regs, 0x0, sizeof(uint64_t) * MAX_BPF_REG);
  const struct bpf_insn *i = insns;
  static std::vector<uint64_t *> map_values;
  static std::vector<std::string> strings; // TODO: could clear on exit?

  bpf_map_def *map_attrs = ctx->map_attrs;
  std::vector<int> &map_fds = *ctx->map_fds;
  FILE *output_f = ctx->output_f;

  map_keys keys[map_fds.size()];

  map_values.clear(); // XXX: avoid double free

  regs[BPF_REG_10] = (uintptr_t)stack + sizeof(stack);

  while ((size_t)(i - insns) < ninsns)
    {
      uint64_t dr, sr, si, s1;
      bpf_perf_event_ret tr;

      dr = regs[i->dst_reg];
      sr = regs[i->src_reg];
      si = i->imm;
      s1 = i->code & BPF_X ? sr : si;

      switch (i->code)
	{
	case BPF_LDX | BPF_MEM | BPF_B:
	  dr = *(uint8_t *)((uintptr_t)sr + i->off);
	  break;
	case BPF_LDX | BPF_MEM | BPF_H:
	  dr = *(uint16_t *)((uintptr_t)sr + i->off);
	  break;
	case BPF_LDX | BPF_MEM | BPF_W:
	  dr = *(uint32_t *)((uintptr_t)sr + i->off);
	  break;
	case BPF_LDX | BPF_MEM | BPF_DW:
	  dr = *(uint64_t *)((uintptr_t)sr + i->off);
	  break;

	case BPF_ST | BPF_MEM | BPF_B:
	  sr = si;
	  /* Fallthrough */
	case BPF_STX | BPF_MEM | BPF_B:
	  *(uint8_t *)((uintptr_t)dr + i->off) = sr;
	  goto nowrite;
	case BPF_ST | BPF_MEM | BPF_H:
	  sr = si;
	  /* Fallthrough */
	case BPF_STX | BPF_MEM | BPF_H:
	  *(uint16_t *)((uintptr_t)dr + i->off) = sr;
	  goto nowrite;
	case BPF_ST | BPF_MEM | BPF_W:
	  sr = si;
	  /* Fallthrough */
	case BPF_STX | BPF_MEM | BPF_W:
	  *(uint32_t *)((uintptr_t)dr + i->off) = sr;
	  goto nowrite;
	case BPF_ST | BPF_MEM | BPF_DW:
	  sr = si;
	  /* Fallthrough */
	case BPF_STX | BPF_MEM | BPF_DW:
	  *(uint64_t *)((uintptr_t)dr + i->off) = sr;
	  goto nowrite;

	case BPF_ALU64 | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_K:  dr += s1; break;
	case BPF_ALU64 | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_K:  dr -= s1; break;
	case BPF_ALU64 | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_K:  dr &= s1; break;
	case BPF_ALU64 | BPF_OR  | BPF_X:
	case BPF_ALU64 | BPF_OR  | BPF_K:  dr |= s1; break;
	case BPF_ALU64 | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_LSH | BPF_K:  dr <<= s1; break;
	case BPF_ALU64 | BPF_RSH | BPF_X:
	case BPF_ALU64 | BPF_RSH | BPF_K:  dr >>= s1; break;
	case BPF_ALU64 | BPF_XOR | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_K:  dr ^= s1; break;
	case BPF_ALU64 | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_K:  dr *= s1; break;
	case BPF_ALU64 | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_K:  dr = s1; break;
	case BPF_ALU64 | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_K: dr = (int64_t)dr >> s1; break;
	case BPF_ALU64 | BPF_NEG:	   dr = -sr; break;
	case BPF_ALU64 | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_DIV | BPF_K:
	  if (s1 == 0)
            {
              // TODO: Signal a proper error.
              result = 0; goto cleanup;
            }
	  dr /= s1;
	  break;
	case BPF_ALU64 | BPF_MOD | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_K:
	  if (s1 == 0)
            {
              // TODO: Signal a proper error.
              result = 0; goto cleanup;
            }
	  dr %= s1;
	  break;

	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU | BPF_ADD | BPF_K:  dr = (uint32_t)(dr + s1); break;
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU | BPF_SUB | BPF_K:  dr = (uint32_t)(dr - s1); break;
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU | BPF_AND | BPF_K:  dr = (uint32_t)(dr & s1); break;
	case BPF_ALU | BPF_OR  | BPF_X:
	case BPF_ALU | BPF_OR  | BPF_K:  dr = (uint32_t)(dr | s1); break;
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU | BPF_LSH | BPF_K:
          // XXX: signal to coverity that we really do want a 32-bit result
          dr = (uint64_t)((uint32_t)dr << s1); break;
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU | BPF_RSH | BPF_K:  dr = (uint32_t)dr >> s1; break;
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU | BPF_XOR | BPF_K:  dr = (uint32_t)(dr ^ s1); break;
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU | BPF_MUL | BPF_K:  dr = (uint32_t)(dr * s1); break;
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU | BPF_MOV | BPF_K:  dr = (uint32_t)s1; break;
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU | BPF_ARSH | BPF_K: dr = (int32_t)dr >> s1; break;
	case BPF_ALU | BPF_NEG:		 dr = -(uint32_t)sr; break;
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU | BPF_DIV | BPF_K:
	  if ((uint32_t)s1 == 0)
            {
              // TODO: Signal a proper error.
              result = 0; goto cleanup;
            }
	  dr = (uint32_t)dr / (uint32_t)s1;
	  break;
	case BPF_ALU | BPF_MOD | BPF_X:
	case BPF_ALU | BPF_MOD | BPF_K:
	  if ((uint32_t)s1 == 0)
            {
              // TODO: Signal a proper error.
              result = 0; goto cleanup;
            }
	  dr = (uint32_t)dr % (uint32_t)s1;
	  break;

	case BPF_LD | BPF_IMM | BPF_DW:
	  switch (i->src_reg)
	    {
	    case 0:
	      dr = (uint32_t)si | ((uint64_t)i[1].imm << 32);
	      break;
	    case BPF_PSEUDO_MAP_FD:
	      if (si >= map_fds.size())
                {
                  // TODO: Signal a proper error.
                  result = 0;
                  goto cleanup;
                }
	      dr = si;
	      break;
	    default:
	      abort();
	    }
	  regs[i->dst_reg] = dr;
	  i += 2;
	  continue;

	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JEQ | BPF_K:
	  if (dr == s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_K:
	  if (dr != s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_K:
	  if (dr > s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_K:
	  if (dr >= s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_K:
	  if ((int64_t)dr > (int64_t)s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_K:
	  if ((int64_t)dr >= (int64_t)s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_K:
	  if (dr & s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JA:
	dojmp:
	  i += 1 + i->off;
	  continue;

	case BPF_JMP | BPF_CALL:
	  switch (si)
	    {
	    case BPF_FUNC_map_lookup_elem:
	      {
                // allocate correctly sized buffer and store it in map_values
                uint64_t *lookup_tmp = (uint64_t *)malloc(map_attrs[regs[1]].value_size);
                map_values.push_back(lookup_tmp);

	        int res = bpf_lookup_elem(map_fds[regs[1]], as_ptr(regs[2]),
			                  as_ptr(lookup_tmp));

	        if (res)
		  // element could not be found
	          dr = 0;
	        else
	          dr = as_int(lookup_tmp);
	      }
	      break;
	    case BPF_FUNC_map_update_elem:
	      dr = bpf_update_elem(map_fds[regs[1]], as_ptr(regs[2]),
			           as_ptr(regs[3]), regs[4]);
	      break;
	    case BPF_FUNC_map_delete_elem:
	      dr = bpf_delete_elem(map_fds[regs[1]], as_ptr(regs[2]));
	      break;
	    case BPF_FUNC_ktime_get_ns:
              dr = bpf_ktime_get_ns();
              break;
            case BPF_FUNC_perf_event_output:
              /* XXX ignored, but could be checked: regs[1], regs[2], regs[3] */
              tr = bpf_handle_transport_msg
                ((void *)regs[4], (size_t)regs[5], ctx);
              /* Normalize return value to match the helper API.
                 XXX: May want to look at errno as well? */
              dr = (tr != LIBBPF_PERF_EVENT_ERROR) ? 0 : -1;
              break;
	    case BPF_FUNC_trace_printk:
              /* XXX no longer need this code after PR22330 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
              // regs[2] is the strlen(regs[1]) - not used by printf(3);
              // instead we assume regs[1] string is \0 terminated
	      dr = fprintf(output_f, remove_tag(as_str(regs[1])).c_str(),
                           /*regs[2],*/ regs[3], regs[4], regs[5]);
              fflush(output_f);
#pragma GCC diagnostic pop
	      break;
            case bpf::BPF_FUNC_sprintf:
              dr = bpf_sprintf(strings, as_str(regs[1]),
                               regs[3], regs[4], regs[5]);
              break;
            case bpf::BPF_FUNC_map_get_next_key:
              dr = map_get_next_key(regs[1], regs[2], regs[3],
                                    regs[4], regs[5],
                                    ctx, keys[regs[1]]);
              break;
            case bpf::BPF_FUNC_stapbpf_stat_get:
              dr = stapbpf_stat_get((bpf::globals::agg_idx)regs[1], regs[2],
                                     bpf::globals::deintern_sc_type(regs[3]), ctx);
              break;
	    default:
	      abort();
	    }
	  regs[0] = dr;
	  regs[1] = 0xea7bee75;
	  regs[2] = 0xea7bee75;
	  regs[3] = 0xea7bee75;
	  regs[4] = 0xea7bee75;
          regs[5] = 0xea7bee75;
	  goto nowrite;

	case BPF_JMP | BPF_EXIT:
	  result = regs[0];
          goto cleanup;

	default:
	  abort();
	}

      regs[i->dst_reg] = dr;
    nowrite:
      i++;
    }
  result = 0;
 cleanup:
  for (uint64_t *ptr : map_values)
    free(ptr);
  map_values.clear(); // XXX: avoid double free
  return result;
}
