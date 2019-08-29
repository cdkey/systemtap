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

#include <sys/time.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <map>
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

// Used with map_get_next_key to store and sort key -> <don'tcare> or
// value -> key mappings. The latter are used to sort by value and
// return key. The int maps use signed type so that negative values
// are properly sorted.
struct map_keys {
  std::vector<std::map<int64_t, int64_t>> int_keyvals;
  std::vector<std::map<std::string, std::string>> str_keyvals;
  std::vector<std::map<std::string, int64_t>> intstr_keyvals;
  std::vector<std::map<int64_t, std::string>> strint_keyvals;
};

void
convert_int_key(uint64_t *kp, int64_t &key)
{
  key = (int64_t)*kp;
}

void
convert_str_key(uint64_t *kp, std::string &key)
{
  key = std::string((char *)kp, BPF_MAXSTRINGLEN_PLUS);
}

void
convert_int_kp(const int64_t &key, uint64_t *kp)
{
  *kp = (uint64_t)key;
}

void
convert_str_kp(const std::string &key, uint64_t *kp,
               std::vector<std::string> &strings)
{
  std::string str(key);
  strings.push_back(str);
  *kp = reinterpret_cast<uint64_t>(strings.back().c_str());
}

template<typename K>
void
convert_key(uint64_t *kp, K &key)
{
  if (std::is_same<K, int64_t>::value)
    convert_int_key(kp, (int64_t&)key);
  else if (std::is_same<K, std::string>::value)
    convert_str_key(kp, (std::string&)key);
  else
    stapbpf_abort("bpf_map_get_next_key BUG: unknown map key/value type");
}

template<typename K>
void
convert_kp(const K &key, uint64_t *kp, std::vector<std::string> &strings)
{
  if (std::is_same<K, int64_t>::value)
    convert_int_kp((int64_t&)key, kp);
  else if (std::is_same<K, std::string>::value)
    convert_str_kp((std::string&)key, kp, strings);
  else
    stapbpf_abort("bpf_map_get_next_key BUG: unknown map key/value type");
}

template<typename K>
int
compute_key_size()
{
  if (std::is_same<K, int64_t>::value)
    return sizeof(int64_t);
  else if (std::is_same<K, std::string>::value)
    return BPF_MAXSTRINGLEN;
  else
    stapbpf_abort("bpf_map_get_next_key BUG: unknown map key/value type");
  return 0;
}

template<typename K, typename V>
int map_sort(std::vector<std::map<V,K>> &keyvals,
             bool use_key, int map_fd)
{
  // Handle both uint64_t and string types.
  //
  // XXX: Copy strings with memcpy() and add a safety NUL. This avoids
  // labyrinth of contradictory compiler warnings on different
  // platforms. Worth reviewing.
  char _k[BPF_MAXSTRINGLEN_PLUS], _n[BPF_MAXSTRINGLEN_PLUS];
  _k[BPF_MAXSTRINGLEN] = _n[BPF_MAXSTRINGLEN] = '\0';
  uint64_t *kp = (uint64_t *)_k, *np = (uint64_t *)_n;
  std::map<V,K> s;

  int key_size = compute_key_size<K>();
  //int value_size = compute_key_size<V>();

  int rc = bpf_get_next_key(map_fd, 0, as_ptr(np));
  while (!rc)
    {
      K key; V value;
      convert_key(np, key);
      if (use_key)
        convert_key(np, value);
      else
        {
          char _v[BPF_MAXSTRINGLEN_PLUS];
          _v[BPF_MAXSTRINGLEN] = '\0';
          uint64_t *vp = (uint64_t *)_v;
          int res = bpf_lookup_elem(map_fd, as_ptr(np), as_ptr(vp));
          if (res) // element could not be found
            stapbpf_abort("bpf_map_get_next_key BUG: could not find key " \
                          "returned by bpf_get_next_key");
          convert_key(vp, value);
        }
      s.insert(std::make_pair(value, key));
      memcpy(kp, np, key_size);
      rc = bpf_get_next_key(map_fd, as_ptr(kp), as_ptr(np));
    }

  if (s.empty())
    return -1;
  keyvals.push_back(s);
  return 0;
}

template<typename K, typename V>
int map_next(std::vector<std::map<V,K>> &keyvals,
             int64_t next_key, int sort_direction,
             std::vector<std::string> &strings)
{
  std::map<V,K> &s = keyvals.back();
  K skey; V sval;

  if (sort_direction > 0)
    {
      auto it = s.begin();
      if (it == s.end())
        return -1;
      skey = it->second;
      sval = it->first;
      convert_kp(skey, (uint64_t *)next_key, strings);
    }
  else // sort_direction < 0
    {
      auto it = s.rbegin();
      if (it == s.rend())
        return -1;
      skey = it->second;
      sval = it->first;
      convert_kp(skey, (uint64_t *)next_key, strings);
    }

  s.erase(sval);
  return 0;
}

// Wrapper for bpf_get_next_key that includes logic for accessing
// keys in ascending or descending order, or
// (PR23858) in ascending or descending order by value.
int
map_get_next_key(int fd_idx, int64_t key, int64_t next_key,
                 uint64_t sort_flags, int64_t limit,
                 bpf_transport_context *ctx, map_keys &keys,
                 std::vector<std::string> &strings)
{
  int fd = (*ctx->map_fds)[fd_idx];
  unsigned sort_column = GET_SORT_COLUMN(sort_flags);
  int sort_direction = GET_SORT_DIRECTION(sort_flags);
  // TODO PR24528: also handle s->sort_aggr for stat aggregates.
  //fprintf(stderr, "DEBUG called map_get_next_key fd=%d sort_column=%u sort_direction=%d key=%lx next_key=%lx limit=%ld\n", fd, sort_column, sort_direction, key, next_key, limit);

  // XXX: s->sort_column may be uninitialized if s->sort_direction == 0
  if (sort_direction == 0)
    sort_column = 0;

  bool use_value = (sort_column == 0);
  bool use_key = (sort_column == 1);

  // XXX: May want to pass the actual key/value type. For now guess from size:
  bool key_str = (ctx->map_attrs[fd_idx].key_size == BPF_MAXSTRINGLEN);
  bool is_str = false;
  if (use_value)
    is_str = (ctx->map_attrs[fd_idx].value_size == BPF_MAXSTRINGLEN);
  else if (use_key)
    is_str = key_str;
  else
    stapbpf_abort("unknown sort column");

  //std::cerr << "DEBUG limit==" << limit << ", keys.str_keyvals.size()==" << keys.str_keyvals.size() << std::endl;
  // Final iteration, therefore keys.back() is no longer needed:
  if (limit == 0)
    {
      if (!key)
        // PR24811: If key is not set, there's nothing to pop.
        return -1;

      if (key_str && is_str)
        keys.str_keyvals.pop_back();
      else if (!key_str && !is_str)
        keys.int_keyvals.pop_back();
      else if (!key_str && is_str)
        keys.intstr_keyvals.pop_back();
      else if (key_str && !is_str)
        keys.strint_keyvals.pop_back();
      //std::cerr << "DEBUG after pop keys.str_keyvals.size()==" << keys.str_keyvals.size() << std::endl;
      return -1;
    }

  if (sort_direction == 0)
    {
      if (!key_str)
        return bpf_get_next_key(fd, as_ptr(key), as_ptr(next_key));

      // XXX Handle string values being passed as pointers.
      char _n[BPF_MAXSTRINGLEN_PLUS];
      uint64_t *kp = key == 0x0 ? (uint64_t *)0x0 : *(uint64_t **)key;
      uint64_t *np = (uint64_t *)_n;
      int rc = bpf_get_next_key(fd, as_ptr(kp), as_ptr(np));
      if (!rc)
        {
          std::string next_key2(_n, BPF_MAXSTRINGLEN);
          convert_kp(next_key2, (uint64_t *)next_key, strings);
        }
      return rc;
    }

  // Beginning of iteration; populate a new set of keys/values for
  // the map specified by fd. Multiple sets can be associated
  // with a single map during execution of nested foreach loops.
  int rc = 0;
  if (!key && key_str && is_str)
    {
      rc = map_sort<std::string, std::string>(keys.str_keyvals, use_key, fd);
      //std::cerr << "DEBUG after push keys.str_keyvals.size()==" << keys.str_keyvals.size() << " " << keys.str_keyvals.back().size() << std::endl;
      //for (auto kv : keys.str_keyvals.back()) std::cerr << "DEBUG " << kv.first << " --> " << kv.second << std::endl;
    }
  else if (!key && !key_str && !is_str)
    {
      rc = map_sort<int64_t, int64_t>(keys.int_keyvals, use_key, fd);
    }
  else if (!key && !key_str && is_str)
    {
      rc = map_sort<int64_t, std::string>(keys.intstr_keyvals, use_key, fd);
    }
  else if (!key && key_str && !is_str)
    {
      rc = map_sort<std::string, int64_t>(keys.strint_keyvals, use_key, fd);
    }
  else if (!key)
    stapbpf_abort("BUG: bpf_map_get_next_key unidentified key/val types");
  if (rc < 0) // map is empty
    return -1;

  if (key_str && is_str)
    {
      rc = map_next<std::string, std::string>(keys.str_keyvals, next_key,
                                              sort_direction, strings);
      //std::cerr << "DEBUG after next keys.str_keyvals.size()==" << keys.str_keyvals.size() << " " << keys.str_keyvals.back().size() << std::endl;
      if (rc < 0) // map is empty
        {
          keys.str_keyvals.pop_back();
          //std::cerr << "DEBUG NOLIMIT after pop keys.str_keyvals.size()==" << keys.str_keyvals.size() << std::endl;
          return -1;
        }
    }
  else if (!key_str && !is_str)
    {
      rc = map_next<int64_t, int64_t>(keys.int_keyvals, next_key,
                                      sort_direction, strings);
      if (rc < 0) // map is empty
        {
          keys.int_keyvals.pop_back();
          return -1;
        }
    }
  else if (!key_str && is_str)
    {
      rc = map_next<int64_t, std::string>(keys.intstr_keyvals, next_key,
                                          sort_direction, strings);
      if (rc < 0) // map is empty
        {
          keys.intstr_keyvals.pop_back();
          return -1;
        }
    }
  else // key_str && !is_str
    {
      rc = map_next<std::string, int64_t>(keys.strint_keyvals, next_key,
                                          sort_direction, strings);
      if (rc < 0) // map is empty
        {
          keys.strint_keyvals.pop_back();
          return -1;
        }
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
  uint64_t stack[512 / 8];
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
                                    ctx, keys[regs[1]], strings);
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
