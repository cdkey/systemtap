/* bpfinterp.cxx - SystemTap BPF interpreter
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
 * Copyright (C) 2016-2021 Red Hat, Inc.
 *
 */

#include <sys/time.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <deque>
#include <algorithm>
#include <type_traits>
#include <inttypes.h>
#include "bpfinterp.h"
#include "libbpf.h"
#include "../bpf-internal.h"
#include "../util.h"

#define stapbpf_abort(reason) \
  ({ fprintf(stderr, _("bpfinterp.cxx:%d: %s\n"), \
             __LINE__, (reason));                \
    abort(); })
#define stapbpf_just_abort() stapbpf_abort("bpf userspace interpreter error")

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

// Represents an in-progress foreach loop, including sorted keys/vals:
struct foreach_state {
  uint64_t foreach_id;

  // Used to store and sort (col,key) or (val,key) pairs for
  // iteration, where col is a sort column of the key:
  std::deque<std::pair<std::string, uint64_t *>> str_sorted;
  std::deque<std::pair<int64_t, uint64_t *>> int_sorted;

  // Used to track keys for deallocation by foreach_state_cleanup:
  std::vector<uint64_t *> keys;
};

// The interpreter maintains a stack of foreach_states,
// with each nested foreach loop pushing onto the stack:
typedef std::vector<foreach_state> foreach_stack;

#define foreach_info bpf::globals::foreach_info

void
foreach_state_add(const foreach_info &fi, foreach_state &s,
                  uint64_t *kp, uint64_t *colp,
                  bool scalar_long)
{
  // extract col_str, col_long from colp
  std::string col_str;
  bool use_str_col = false;
  int64_t col_long;
  //bool use_long_col = false;
  if (scalar_long)
    {
      // colp points to a scalar long value
      //use_long_col = true;
      col_long = *colp;
    }
  else if (fi.sort_column == 0 /* use_value */
           || fi.sort_column_ofs == -1 /* !key_composite */)
    {
      // colp is a single string
      use_str_col = true;
      std::string col_str2((char *)colp, BPF_MAXSTRINGLEN);
      col_str = col_str2;
    }
  else
    {
      // colp contains a column at fi.sort_column_ofs
      colp = (uint64_t *)(((char *)colp)+fi.sort_column_ofs);
      if (fi.sort_column_size == BPF_MAXSTRINGLEN)
        {
          use_str_col = true;
          std::string col_str3((char *)colp, BPF_MAXSTRINGLEN);
          col_str = col_str3;
        }
      else
        {
          //use_long_col = true;
          col_long = *colp;
        }
    }

  // copy and save key
  uint64_t *kp2 = (uint64_t *)malloc(fi.keysize);
  memcpy(kp2, kp, fi.keysize);
  s.keys.push_back(kp2);

  // save (col,key) pair
  if (use_str_col)
    {
      std::pair<std::string, uint64_t *> item_str(col_str, kp2);
      s.str_sorted.push_back(item_str);
    }
  else // use_long_col
    {
      std::pair<int64_t, uint64_t *> item_long(col_long, kp2);
      s.int_sorted.push_back(item_long);
    }
}

bool
foreach_cmp_str(const std::pair<std::string, void *> &a,
                const std::pair<std::string, void *> &b)
{
  return a.first < b.first;
}

bool
foreach_cmp_int(const std::pair<int64_t, void *> &a,
                const std::pair<int64_t, void *> &b)
{
  return a.first < b.first;
}

void
foreach_state_sort(foreach_state &s)
{
  if (!s.str_sorted.empty())
    {
      std::stable_sort(s.str_sorted.begin(), s.str_sorted.end(),
                       foreach_cmp_str);
    }
  if (!s.int_sorted.empty())
    {
      std::stable_sort(s.int_sorted.begin(), s.int_sorted.end(),
                       foreach_cmp_int);
    }
}

bool
foreach_state_empty(const foreach_state &s)
{
  return s.str_sorted.empty() && s.int_sorted.empty();
}

void
convert_key(const foreach_info &fi,
            uint64_t *kp, uint64_t *next_kp,
            std::vector<std::string> &strings,
            std::vector<uint64_t *> &map_values)
{
  bool scalar_long = fi.sort_column_ofs == -1 /* !key_composite */
    && fi.keysize != BPF_MAXSTRINGLEN /* key_long */;
  bool scalar_str = fi.sort_column_ofs == -1 /* !key_composite */
    && fi.keysize == BPF_MAXSTRINGLEN /* key_str */;
  if (scalar_long)
    {
      // handle scalar long keys being passed directly
      *next_kp = *kp;
      return;
    }
  if (scalar_str)
    {
      // handle string keys being passed as pointers
      // TODO: Could merge strings into map_values:
      std::string str((char*)kp, BPF_MAXSTRINGLEN);
      strings.push_back(str);
      *next_kp = reinterpret_cast<uint64_t>(strings.back().c_str());
      return;
    }

  // handle string composite keys being passed as pointers
  // allocate correctly sized buffer and store it in map_values:
  uint64_t *lookup_tmp = (uint64_t*)malloc(fi.keysize);
  memcpy(lookup_tmp, kp, fi.keysize);
  map_values.push_back(lookup_tmp);
  *next_kp = reinterpret_cast<uint64_t>(map_values.back());
}

template<typename T>
int
_foreach_state_next(const foreach_info &fi, /* XXX foreach_state &s, */
                    std::deque<std::pair<T,uint64_t*>> &sorted,
                    int64_t key, int64_t next_key,
                    std::vector<std::string> &strings,
                    std::vector<uint64_t *> &map_values)
{
  (void)key; // XXX unused; see comment in foreach_state_next()

  if (sorted.empty())
    return -1;

  if (fi.sort_direction > 0)
    {
      std::pair<T,uint64_t*> item = sorted.front();
      convert_key(fi, item.second, (uint64_t *)next_key,
                  strings, map_values);
      sorted.pop_front();
    }
  else // sort_direction < 0
    {
      std::pair<T,uint64_t*> item = sorted.back();
      convert_key(fi, item.second, (uint64_t *)next_key,
                  strings, map_values);
      sorted.pop_back();
    }
  return 0;
}

int
foreach_state_next(const foreach_info &fi, foreach_state &s,
                   int64_t key, int64_t next_key,
                   std::vector<std::string> &strings,
                   std::vector<uint64_t *> &map_values)
{
  // TODO: Sanity check that we are continuing the same iteration?
  // Would require storing key in foreach_state.
  //
  // XXX Otherwise the code assumes that the BPF probe exactly follows
  // a foreach pattern, always passing the returned key as the next
  // key and not trying to 'start iteration in the middle'.
  if (!s.str_sorted.empty())
    {
      return _foreach_state_next<std::string>(fi, /* XXX s, */
                                              s.str_sorted,
                                              key, next_key,
                                              strings, map_values);
    }
  if (!s.int_sorted.empty())
    {
      return _foreach_state_next<int64_t>(fi, /* XXX s, */
                                          s.int_sorted,
                                          key, next_key,
                                          strings, map_values);
    }
  return -1;
}

void
foreach_state_cleanup(foreach_state &s)
{
  for (uint64_t *ptr : s.keys)
    free(ptr);
}

// Wrapper for bpf_get_next_key that includes logic for accessing
// keys in ascending or descending order, or
// (PR23858) in ascending or descending order by value.
int
map_get_next_key(int fd_idx, int64_t key, int64_t next_key,
                 uint64_t foreach_id, int64_t limit,
                 bpf_transport_context *ctx, foreach_stack &foreach_ctx,
                 std::vector<std::string> &strings,
                 std::vector<uint64_t *> &map_values)
{
  int fd = (*ctx->map_fds)[fd_idx];

  // Retrieve foreach loop info
  foreach_info fi;
  bool have_fi = !ctx->foreach_loop_info->empty()
    && ctx->foreach_loop_info->size() > foreach_id;
  fi.sort_column = 1;
  fi.sort_direction = 0;
  fi.keysize = 0;
  fi.sort_column_size = 0;
  fi.sort_column_ofs = 0;
  if (!have_fi)
    {
      // XXX Backwards compatibility for older .bo's using
      // sort_flags and no foreach_loop_info table.
      uint64_t sort_flags = foreach_id;
      fi.sort_column = GET_SORT_COLUMN(sort_flags);
      fi.sort_direction = GET_SORT_DIRECTION(sort_flags);

      // XXX The entire key is a single column.
      fi.keysize = ctx->map_attrs[fd_idx].key_size;
      fi.sort_column_size = fi.keysize;
      fi.sort_column_ofs = -1; // XXX use entire key
    }
  else
    {
      fi = ctx->foreach_loop_info->operator[](foreach_id);
      //assert(fi.keysize == ctx->map_attrs[fd_idx].key_size);
      // TODO PR24528: also handle s->sort_aggr for stat aggregates
    }
  //fprintf(stderr, "DEBUG called map_get_next_key fd=%d sort_column=%u sort_direction=%d key=%lx next_key=%lx limit=%ld\n", fd, fi.sort_column, fi.sort_direction, key, next_key, limit);

  // Identify type of key, value
  bool use_val = fi.sort_column == 0;
  bool key_composite = fi.sort_column_ofs != -1;
  bool key_long = false;
  bool key_str = false;
  if (!key_composite)
    {
      // XXX If the key has one column, it is either
      // a string (BPF_MAXSTRINGLEN) or a scalar long.
      key_long = fi.keysize != BPF_MAXSTRINGLEN;
      key_str = fi.keysize == BPF_MAXSTRINGLEN;
    }
  bool val_long = ctx->map_attrs[fd_idx].value_size != BPF_MAXSTRINGLEN;
  //bool val_str = !val_long;

  // Check iteration limit
  if (limit == 0)
    {
      // Final iteration, therefore foreach_ctx.back() is no longer needed

      // PR24811 att1: If key is not set, the map is empty and the
      // context wasn't created. Only pop with a nonzero key.
      //
      // XXX: A malformed .bo could still mess with this check
      // by issuing map_get_next_key(key=?,limit=0) calls
      // outside the usual foreach pattern.
      //if (!key)
      //  return -1;

      // PR24811 att2: Check if the context for this foreach_id was created.
      // It might not have been if the limit is zero on the first call.
      if (foreach_ctx.empty()
          || foreach_ctx.back().foreach_id != foreach_id)
        return -1;

      foreach_state_cleanup(foreach_ctx.back());
      foreach_ctx.pop_back();
      return -1;
    }

  // Handle fi.sort_direction==0, where no foreach_ctx is needed
  if (fi.sort_direction == 0)
    {
      // handle scalar long values being passed directly
      if (key_long)
        return bpf_get_next_key(fd, as_ptr(key), as_ptr(next_key));

      // handle string and composite keys being passed as pointers
      char _n[BPF_MAXKEYLEN_PLUS];
      uint64_t *kp = key == 0x0 ? (uint64_t *)0x0 : *(uint64_t **)key;
      uint64_t *np = (uint64_t *)_n;
      int rc = bpf_get_next_key(fd, as_ptr(kp), as_ptr(np));
      if (!rc && key_str)
        {
          // TODO: Could merge strings into map_values:
          std::string next_key2(_n, BPF_MAXSTRINGLEN);
          strings.push_back(next_key2);
          *(uint64_t *)next_key =
            reinterpret_cast<uint64_t>(strings.back().c_str());
        }
      else if (!rc)
        {
          // allocate correctly sized buffer and store it in map_values:
          uint64_t *lookup_tmp = (uint64_t*)malloc(fi.keysize);
          memcpy(lookup_tmp, _n, fi.keysize);
          map_values.push_back(lookup_tmp);
          *(uint64_t *)next_key =
            reinterpret_cast<uint64_t>(map_values.back());
        }
      return rc;
    }

  // Sort the map on initial iteration
  if (!key)
    {
      // handle both uint64_t and string column types
      char _k[BPF_MAXKEYLEN_PLUS], _n[BPF_MAXKEYLEN_PLUS];
      _k[BPF_MAXSTRINGLEN] = _k[BPF_MAXKEYLEN] = '\0';
      _n[BPF_MAXSTRINGLEN] = _n[BPF_MAXKEYLEN] = '\0';
      uint64_t *kp = (uint64_t *)_k;
      uint64_t *np = (uint64_t *)_n;
      foreach_state s;

      int rc = bpf_get_next_key(fd, 0, as_ptr(np));
      while (!rc)
        {
          if (use_val)
            {
              char _v[BPF_MAXKEYLEN_PLUS];
              _v[BPF_MAXSTRINGLEN] = _v[BPF_MAXKEYLEN] = '\0';
              uint64_t *vp = (uint64_t *)_v;
              int res = bpf_lookup_elem(fd, as_ptr(np), as_ptr(vp));
              if (res) // element could not be found
                stapbpf_abort("bpf_map_get_next_key BUG: could not find key " \
                              "returned by bpf_get_next_key");
              foreach_state_add(fi, s, np, vp, val_long);
            }
          else
            {
              // foreach_state_add extracts the column from np
              foreach_state_add(fi, s, np, np, key_long);
            }
          memcpy(kp, np, fi.keysize);
          rc = bpf_get_next_key(fd, as_ptr(kp), as_ptr(np));
        }
      foreach_state_sort(s);
      if (foreach_state_empty(s))
        return -1;
      foreach_ctx.push_back(s);
    }

  if (foreach_ctx.empty())
    stapbpf_abort("bpf_map_get_next_key BUG: called outside a foreach loop");

  // Get next value from sorted data
  int rc = foreach_state_next(fi, foreach_ctx.back(), key, next_key,
                              strings, map_values);
  if (rc < 0) // no more elements to return
    {
      foreach_state_cleanup(foreach_ctx.back());
      foreach_ctx.pop_back();
      return -1;
    }
  return 0;
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

uint64_t
bpf_text_str(std::vector<std::string> &strings, char* input, bool quoted)
{
  std::string str(input);
  std::stringstream stream;

  for (std::string::iterator it = str.begin(); it != str.end(); ++it)
    {
      unsigned char c = *it;
      unsigned int i = c;

      if (std::isprint(c) && i < 128 && c != '\\' && c != '"')
        stream << c;
      else 
        {
          stream << '\\';
          switch (c) {
            case '\0': stream << '0'; break; // Not handled by translate_escapes
            case '\a': stream << 'a'; break; // Not handled by translate_escapes
            case '\b': stream << 'b'; break; // Not handled by translate_escapes
            case '\f': stream << 'f'; break;
            case '\n': stream << 'n'; break;
            case '\r': stream << 'r'; break;
            case '\t': stream << 't'; break;
            case '\v': stream << 'v'; break;
            case '"': stream << '"'; break;
            case '\\': stream << '\\'; break;
            default: 
              stream << "x" << std::setfill('0') << std::setw(2) << std::hex << i;
              break;
          }
        }
    } 

  if (quoted)
    strings.push_back("\"" + stream.str() + "\"");
  else  
    strings.push_back(stream.str());

  return reinterpret_cast<uint64_t>(strings.back().c_str());
}

uint64_t
bpf_str_concat(std::vector<std::string> &strings, char* left, char* right)
{
  std::string concat;
  concat += left;
  concat += right;

  strings.push_back(concat);

  // After adding the new string into the vector, the c_str() pointer value
  // will be valid and safe to use 
  return reinterpret_cast<uint64_t>(strings.back().c_str());
}

// Allocates and returns a buffer of percpu data for a stat field:
uint64_t *
stapbpf_stat_get_percpu(bpf::globals::map_idx map, uint64_t idx,
                        bpf_transport_context *ctx)
{
  uint64_t *ret = (uint64_t *)calloc(ctx->ncpus, sizeof(uint64_t));
  int res = bpf_lookup_elem((*ctx->map_fds)[map], as_ptr(idx), ret);
  if (res) {
      // element could not be found
      free(ret);
      return 0;
    }
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
    stapbpf_abort("aggregate could not be found");
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

  // XXX for_each_possible_cpu(i)
  if (count_data) {
    for (unsigned i = 0; i < ctx->ncpus; i++)
	agg.count += count_data[i];
    free(count_data);
  }

  // XXX for_each_possible_cpu(i)
  if (sum_data) {
    for (unsigned i = 0; i < ctx->ncpus; i++)
	agg.sum += sum_data[i];
    free(sum_data);
  }

  // XXX Simplified version of _stp_div64():
  if (agg.count == 0)
    agg.avg_s = 0;
  else
    agg.avg_s = (agg.sum << agg.shift) / agg.count;

  switch (sc_op)
    {
    case sc_average:
      if (agg.count == 0)
        stapbpf_abort("empty aggregate"); // TODO: Should produce proper error.
      return agg.avg_s;

    case sc_count:
      return agg.count;

    case sc_sum:
      return agg.sum;

    case sc_none:
      // should not happen, as sc_none is only used in foreach slots
      stapbpf_abort("unexpected sc_none");

    // TODO PR23476: Not yet implemented.
    case sc_min:
    case sc_max:
    case sc_variance:
    default:
      stapbpf_abort("unsupported aggregate");
    }
}

uint64_t
bpf_ktime_get_ns()
{
  struct timespec t;
  clock_gettime (CLOCK_BOOTTIME, &t);
  return (t.tv_sec * 1000000000) + t.tv_nsec;
}

uint64_t
bpf_gettimeofday_ns()
{
  struct timeval t;
  gettimeofday (&t, NULL);
  return (((t.tv_sec * 1000000) + t.tv_usec) * 1000);
}

uint64_t
bpf_get_target()
{
  return target_pid;
}

uint64_t
bpf_set_procfs_value(char* msg, bpf_transport_context* ctx)
{
  assert(msg != nullptr);

  ctx->procfs_msg = std::string(msg);

  return 0;
}

uint64_t
bpf_append_procfs_value(char* msg, bpf_transport_context* ctx)
{
  assert(msg != nullptr);

  ctx->procfs_msg.append(std::string(msg)); 

  return 0;
}

uint64_t
bpf_get_procfs_value(bpf_transport_context* ctx)
{
  return (uint64_t) (ctx->procfs_msg.data());
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
    case bpf::globals::STP_STORE_ERROR_MSG:
      // Store error message for future printing.
      ctx->error_message.push(std::string((char*) msg_content));
      break;

    case bpf::globals::STP_PRINT_ERROR_MSG:
      // Print error message that was stored previously.
      assert(!ctx->error_message.empty());
      // TODO: Need better color configuration.
      std::cout << "\033[1m\033[31m" << "ERROR: " << "\033[0m" << ctx->error_message.front() << std::endl;
      ctx->error_message.pop();
      break;

    case bpf::globals::STP_ERROR:
      // Signal an exit from the program and communicate a hard error:
      if (bpf_update_elem((*ctx->map_fds)[bpf::globals::internal_map_idx],
                          &exit_key, &exit_val, BPF_ANY) != 0)
        stapbpf_abort("could not set exit status");
      *ctx->error = true;
      return LIBBPF_PERF_EVENT_DONE;

    case bpf::globals::STP_EXIT:
      // Signal an exit from the program:
      if (bpf_update_elem((*ctx->map_fds)[bpf::globals::internal_map_idx],
                          &exit_key, &exit_val, BPF_ANY) != 0)
        stapbpf_abort("could not set exit status");
      return LIBBPF_PERF_EVENT_DONE;

    case bpf::globals::STP_PRINTF_START:
      if (ctx->in_printf)
        stapbpf_abort("printf already started");
      if (msg_size != sizeof(BPF_TRANSPORT_ARG))
        stapbpf_abort("wrong argument size");
      ctx->in_printf = true; ctx->format_no = -1;
      ctx->expected_args = *(BPF_TRANSPORT_ARG*)msg_content;
      break;

    case bpf::globals::STP_PRINTF_END:
      if (!ctx->in_printf)
        stapbpf_abort("printf not started");
      if (ctx->format_no < 0 || ctx->format_no >= (int)ctx->interned_strings->size())
        stapbpf_abort("printf format is missing");
      if (ctx->printf_args.size() != ctx->expected_args)
        stapbpf_abort("wrong number of printf args");

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
        stapbpf_abort("printf not started");
      if (ctx->format_no != -1)
        stapbpf_abort("printf already has format");
      if (msg_size != sizeof(BPF_TRANSPORT_ARG))
        stapbpf_abort("wrong argument size");
      ctx->format_no = *(BPF_TRANSPORT_ARG*)msg_content;
      break;

    // XXX: Could save spurious mallocs by storing ARG_LONG as the void * itself.
    case bpf::globals::STP_PRINTF_ARG_LONG:
    case bpf::globals::STP_PRINTF_ARG_STR:
      if (!ctx->in_printf)
        stapbpf_abort("printf not started");
      arg = malloc(msg_size);
      memcpy(arg, msg_content, msg_size);
      ctx->printf_args.push_back(arg);
      ctx->printf_arg_types.push_back(msg_type);
      break;

    default:
      stapbpf_abort("unknown transport message");
    } 
  return LIBBPF_PERF_EVENT_CONT;
}

uint64_t
bpf_interpret(size_t ninsns, const struct bpf_insn insns[],
              bpf_transport_context *ctx)
{
  uint64_t result = 0; // return value
  uint64_t stack[65536 / 8]; // see MAX_BPF_USER_STACK in bpf-internal.h
  uint64_t regs[MAX_BPF_REG];
  memset(regs, 0x0, sizeof(uint64_t) * MAX_BPF_REG);
  const struct bpf_insn *i = insns;
  static std::vector<uint64_t *> map_values;

  // Multiple threads accessing strings can cause concurrency issues for
  // procfs_probes. However, the procfs_lock should prevent this and thus,
  // clearing it on exit is unecessary for now.
  static std::vector<std::string> strings;

  bpf_map_def *map_attrs = ctx->map_attrs;
  std::vector<int> &map_fds = *ctx->map_fds;
  FILE *output_f = ctx->output_f;

  foreach_stack foreach_ctxs[map_fds.size()];

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
	      stapbpf_just_abort();
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
            case bpf::BPF_FUNC_text_str:
              dr = bpf_text_str(strings, as_str(regs[1]), false);
              break;
            case bpf::BPF_FUNC_string_quoted:
              dr = bpf_text_str(strings, as_str(regs[1]), true);
              break;
            case bpf::BPF_FUNC_str_concat:
              dr = bpf_str_concat(strings, as_str(regs[1]), 
                                  as_str(regs[2]));
              break;
            case bpf::BPF_FUNC_map_get_next_key:
              dr = map_get_next_key(regs[1], regs[2], regs[3],
                                    regs[4], regs[5],
                                    ctx, foreach_ctxs[regs[1]],
                                    strings, map_values);
              break;
            case bpf::BPF_FUNC_stapbpf_stat_get:
              dr = stapbpf_stat_get((bpf::globals::agg_idx)regs[1], regs[2],
                                     bpf::globals::deintern_sc_type(regs[3]), ctx);
              break;
            case bpf::BPF_FUNC_gettimeofday_ns:
              dr = bpf_gettimeofday_ns();
              break;
            case bpf::BPF_FUNC_get_target:
              dr = bpf_get_target();
              break;
            case bpf::BPF_FUNC_set_procfs_value:
              dr = bpf_set_procfs_value(as_str(regs[1]), ctx);
              break;
            case bpf::BPF_FUNC_append_procfs_value:
              dr = bpf_append_procfs_value(as_str(regs[1]), ctx);
              break;
            case bpf::BPF_FUNC_get_procfs_value:
              dr = bpf_get_procfs_value(ctx);
              break;
	    default:
	      stapbpf_abort("unknown helper function");
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
	  stapbpf_abort("unknown bpf opcode");
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
