// bpf internal classes
// Copyright (C) 2016-2019 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#ifndef BPF_INTERNAL_H
#define BPF_INTERNAL_H

#include <iostream>
#include <vector>
#include <cassert>
#include <unordered_set>
#include <unordered_map>
#include "bpf-bitset.h"
#include "staptree.h"

extern "C" {
#include <linux/bpf.h>
}

/* PR23829: These eBPF opcodes were added in recent kernels, and the
   following 'ad hoc' defines are only used by the embedded-code
   assembler.  The code generator will convert these opcodes to
   equivalent operations valid for earlier eBPF. */
#ifndef BPF_JLT
#define BPF_JLT		0xa0	/* LT is unsigned, '<' */
#define BPF_JLE		0xb0	/* LE is unsigned, '<=' */
#define BPF_JSLT	0xc0	/* SLT is signed, '<' */
#define BPF_JSLE	0xd0	/* SLE is signed, '<=' */
#endif

struct systemtap_session;
struct derived_probe;
struct vardecl;

namespace bpf {

// Constants for BPF code generation.
// TODO: BPF_MAX{STRING,FORMAT}LEN,BPF_MAXMAPENTRIES,BPF_MAXSPRINTFLEN should be user-configurable.

#define MAX_BPF_STACK 512
#define BPF_REG_SIZE 8

#define BPF_MAXSTRINGLEN 64
#define BPF_MAXSTRINGLEN_PLUS 65
// #define BPF_MAXSTRINGLEN 128 // TODO: Longer strings require a smarter storage allocator.
// #define BPF_MAXSTRINGLEN_PLUS 129
#define BPF_MAXFORMATLEN 256
#define BPF_MAXPRINTFARGS 32
// #define BPF_MAXPRINTFARGS 3 // Maximum for trace_printk() method.
#define BPF_MAXSPRINTFARGS 3   // Maximum for sprintf() method.

#define BPF_MAXMAPENTRIES 2048
// XXX: BPF_MAXMAPENTRIES may depend on kernel version. May need to experiment with rlimit in instantiate_maps().

// Constants for transport message layout.
// TODO: Try to reduce the size (to __u32) while keeping proper alignment.
#define BPF_TRANSPORT_VAL uint64_t
#define BPF_TRANSPORT_ARG uint64_t
// XXX: BPF_TRANSPORT_ARG is for small numerical arguments, not pe_long values.

// Will print out bpf assembly before and after optimization:
//#define DEBUG_CODEGEN

typedef unsigned short regno;
static const regno max_regno = BPF_MAXINSNS;
static const regno noreg = -1;

typedef unsigned short opcode;

struct insn;

// BPF itself does not provide a full set of comparison codes.
// To make things easy for ourselves, emulate them.
enum condition
{
  EQ, NE, LT, LE, GT, GE, LTU, LEU, GTU, GEU, TEST
};

struct value
{
  enum value_type { UNINIT,
                    IMM,
                    STR, /* <- lowered to HARDREG by the optimizer */
                    HARDREG,
                    TMPREG, /* <- lowered to HARDREG by the optimizer */ };

  value_type type	: 16;
  regno reg_val		: 16;
  int64_t imm_val;
  std::string str_val;

  bool format_str; // marks format string
  exp_type format_type; // marks format arguments

  value(value_type t = UNINIT, regno r = noreg, int64_t c = 0,
        std::string s = "", bool format_str = false)
    : type(t), reg_val(r), imm_val(c), str_val(s),
      format_str(format_str), format_type(pe_unknown)
  { }

  static value mk_imm(int64_t i) { return value(IMM, noreg, i); }
  static value mk_str(std::string s, bool format_str = false) {
    return value(STR, noreg, 0, s, format_str);
  }
  static value mk_reg(regno r) { return value(TMPREG, r); }
  static value mk_hardreg(regno r) { return value(HARDREG, r); }

  bool is_reg() const { return type >= HARDREG; }
  bool is_imm() const { return type == IMM; }
  bool is_str() const { return type == STR; }
  bool is_format() const { assert(is_str()); return format_str; }

  regno reg() const { assert(is_reg()); return reg_val; }
  int64_t imm() const { assert(is_imm()); return imm_val; }
  std::string str() const { assert(is_str()); return str_val; }

  std::ostream& print(std::ostream &) const;
};

inline std::ostream&
operator<< (std::ostream &o, const value &v)
{
  return v.print (o);
}

inline bool is_call(opcode c) { return c == (BPF_JMP | BPF_CALL); }
bool is_jmp(opcode c);
bool is_move(opcode c);
bool is_ldst(opcode c);
bool is_binary(opcode c);
bool is_commutative(opcode c);

void init_bpf_helper_tables();
const char *bpf_function_name (unsigned id);
bpf_func_id bpf_function_id (const std::string &name);
unsigned bpf_function_nargs (unsigned id);

const opcode BPF_LD_MAP = BPF_LD | BPF_IMM | BPF_DW | (BPF_PSEUDO_MAP_FD << 8);

// Not actual BPF helpers, but treating them as such simplifies some of the
// interpreter logic. We give them IDs that shouldn't conflict with IDs of
// real BPF helpers.
#define __STAPBPF_FUNC_MAPPER(FN) \
  FN(map_get_next_key),           \
  FN(sprintf),                    \
  FN(stapbpf_stat_get),           \
  FN(gettimeofday_ns),
const bpf_func_id BPF_FUNC_map_get_next_key    = (bpf_func_id) -1;
const bpf_func_id BPF_FUNC_sprintf             = (bpf_func_id) -2;
const bpf_func_id BPF_FUNC_stapbpf_stat_get    = (bpf_func_id) -3;
const bpf_func_id BPF_FUNC_gettimeofday_ns     = (bpf_func_id) -4;


struct insn
{
  opcode code		: 16;	// The usual bpf opcode
  unsigned id		: 16;	// Context-dependent unique identifier
  signed off		: 16;	// The memory offset operand
  value *dest;			// The usual destination operand
  value *src0;			// The destination input, pre-allocation
  value *src1;			// The usual source register operand
  insn *prev, *next;		// Linked list of insns in the block
#ifdef DEBUG_CODEGEN
  std::string note;             // For additional diagnostics.
#endif

  insn();

  bool is_jmp() const { return bpf::is_jmp(code); }
  bool is_call() const { return bpf::is_call(code); }
  bool is_move() const { return bpf::is_move(code); }
  bool is_ldst() const { return bpf::is_ldst(code); }
  bool is_binary() const { return bpf::is_binary(code); }
  bool is_commutative() const { return bpf::is_commutative(code); }

  void mark_sets(bitset::set1_ref &s, bool v) const;
  void mark_uses(bitset::set1_ref &s, bool v) const;

  std::ostream& print(std::ostream &o) const;
};

inline std::ostream&
operator<< (std::ostream &o, const insn &i)
{
  return i.print (o);
}

struct block;
struct edge
{
  block *prev, *next;

  edge(block *p, block *n);
  ~edge();
  void redirect_next(block *n);
};

struct block
{
  typedef std::unordered_set<edge *> edge_set;
  edge_set prevs;		// All incoming edges

  insn *first, *last;		// Linked list of insns in the block
  edge *taken;			// Taken (conditional or not) edge
  edge *fallthru;		// Not taken conditional edge
  unsigned short id;		// Index in cfg

  block(int);
  ~block();
  block *is_forwarder() const;
  void print(std::ostream &o) const;
};

inline std::ostream&
operator<< (std::ostream &o, const block &b)
{
  b.print (o);
  return o;
}

class insn_inserter
{
private:
  insn_inserter();		// not present

public:
  block *b;
  insn *i;
#ifdef DEBUG_CODEGEN
  std::stack<std::string> notes;
#endif

  insn_inserter(block *bb, insn *ii) : b(bb), i(ii) { }
  insn_inserter(block *bb, insn *ii, const std::string& note) : b(bb), i(ii) {
#ifdef DEBUG_CODEGEN
    notes.push(note);
#else
    (void)note; // unused
#endif
  }
  virtual ~insn_inserter() { }
  virtual void insert(insn *i) = 0;

  insn *new_insn();
  block *get_block() const { return b; }
  insn_inserter& operator++ () { if (i) i = i->next; return *this; }
  insn_inserter& operator-- () { if (i) i = i->prev; return *this; }
  operator bool () const { return i != NULL; }
};

struct insn_before_inserter : public insn_inserter
{
  insn_before_inserter() : insn_inserter(NULL, NULL) { }
  insn_before_inserter(block *b, insn *i) : insn_inserter(b,i) { }
  insn_before_inserter(block *b, insn *i, const std::string& note)
    : insn_inserter(b,i,note) { }
  virtual void insert(insn *i);
};

struct insn_after_inserter : public insn_inserter
{
  insn_after_inserter() : insn_inserter(NULL, NULL) { }
  insn_after_inserter(block *b, insn *i) : insn_inserter(b,i) { }
  insn_after_inserter(block *b, insn *i, const std::string& note)
    : insn_inserter(b,i,note) { }
  virtual void insert(insn *i);
};

struct insn_append_inserter : public insn_after_inserter
{
  insn_append_inserter() : insn_after_inserter(NULL, NULL) { }
  insn_append_inserter(block *b) : insn_after_inserter(b, NULL) { }
  insn_append_inserter(block *b, const std::string& note)
    : insn_after_inserter(b, NULL, note) { }
};

struct program
{
  std::vector<block *> blocks;	// All blocks in the program
  block *new_block();

  std::vector<value> hardreg_vals;
  std::vector<value *> reg_vals;

  // Store at most one of each IMM and STR value:
  std::unordered_map<int64_t, value *> imm_map;
  std::unordered_map<std::string, value *> str_map;
  std::unordered_map<std::string, value *> format_map;

  regno max_reg() const { return reg_vals.size() + MAX_BPF_REG; }
  value *lookup_reg(regno r);
  value *new_reg();
  value *new_imm(int64_t);
  value *new_str(std::string, bool format_str = false);

  // The BPF local stack is [0, -512] indexed off BPF_REG_10.
  // The translator has dibs on the low bytes, [0, -max_tmp_space],
  // for use with various function calls that pass data by reference.
  // The register allocator may use [-max_tmp_space, -512] for spills.
  unsigned max_tmp_space;
  void use_tmp_space(unsigned bytes)
  {
    if (max_tmp_space < bytes)
      max_tmp_space = bytes;
    assert(max_tmp_space <= MAX_BPF_STACK);
  }

  void mk_ld(insn_inserter &ins, int sz, value *dest, value *base, int off);
  void mk_st(insn_inserter &ins, int sz, value *base, int off, value *src);
  void mk_unary(insn_inserter &ins, opcode op, value *dest, value *src);
  void mk_binary(insn_inserter &ins, opcode op, value *d,
		 value *s0, value *s1);
  void mk_mov(insn_inserter &ins, value *dest, value *src);
  void mk_call(insn_inserter &ins, enum bpf_func_id id, unsigned nargs);
  void mk_exit(insn_inserter &ins);
  void mk_jmp(insn_inserter &ins, block *dest);
  void mk_jcond(insn_inserter &ins, condition c, value *s0, value *s1,
		block *t, block *f);
  void load_map(insn_inserter &ins, value *dest, int src);

  program();
  ~program();

  void generate();
  void print(std::ostream &) const;
};

// ??? Properly belongs to bpf_unparser but must be visible from bpf-opt.cxx:
value *emit_simple_literal_str(program &this_prog, insn_inserter &this_ins,
                               value *dest, int ofs, const std::string &src,
                               bool zero_pad = false);

inline std::ostream&
operator<< (std::ostream &o, const program &c)
{
  c.print (o);
  return o;
}

struct globals
{
  // The list of BPF maps used to store global data:
  struct bpf_map_def
  {
    unsigned type;
    unsigned key_size;
    unsigned value_size;
    unsigned max_entries;
    unsigned map_flags;
  };
  typedef std::vector<bpf_map_def> map_vect;
  map_vect maps;

  // Used to identify a numbered bpf_map (within map_vect):
  using map_idx = int;

  // How to locate a value within the maps, based on vardecl vd:
  //
  // (1) lookup globals_map[vd] --> yields map_slot ms
  // (2) if ms.is_stat(), vd is an aggregate (scalar_stats, array_stats explained below)
  //   - (s).count --> (scalar_stats['count'])[ms.this_idx][cpuid] if ms.is_scalar()
  //   - (s[key]).count --> (array_stats[vd]['count'])[key][cpuid] otherwise
  // (3) otherwise, vd is a regular value
  //   - v --> (ms.this_map)[ms.this_idx] if ms.is_scalar()
  //   - v[key] --> (ms.this_map)[key] otherwise
  //
  // Above, v is a regular value, s is a statistical aggregate.
  // The indexing operations inside parens are performed at translation time,
  // the indexing operations outside parens are performed at runtime.
  //
  // TODOXXX PR24424: For histogram data, the indexing scheme will be:
  // - (s).histogram[n] --> (scalar_stats['histogram'])[ms.this_idx,n][cpuid]
  // Here, map[idx,n] is map[idx << shift | n] (rudimentary multi-key map).
  struct map_slot {
    map_idx map_id; // -- -1 indicates is_stat()
    int idx;        // -- -1 indicates !is_scalar()
    bool is_scalar() { return idx >= 0; }
    bool is_stat() { return map_id < 0; }
    map_slot(map_idx map_id, int idx) : map_id(map_id), idx(idx) {}
  };
  typedef std::unordered_map<vardecl *, map_slot> globals_map;
  globals_map globals;

  bool empty() { return this->globals.empty(); }

  // PR23476: Each statistical aggregate is represented by a percpu data structure
  // with fields such as count, sum, ... (see struct stat_data in runtime/stat.h).
  using stat_field = std::string; // XXX: could make an enum
  static std::vector<stat_field> stat_fields; // XXX: initialized in bpf-translate.cxx
  static stat_field stat_iter_field; // XXX: used to obtain keys for foreach, in, &c

  // scalar_stats, array_stats: For each stats field, create one map
  // for scalar aggregates, plus one map per one-dimensional array of
  // aggregates.
  typedef std::map<stat_field, map_idx> stats_map;
  stats_map scalar_stats;
  std::unordered_map<vardecl *, stats_map> array_stats;

  // XXX: Used to store stats_map elements in a canonical order for serialization:
  typedef std::vector<map_idx> interned_stats_map;
  static interned_stats_map intern_stats_map(const stats_map &sm);
  static stats_map deintern_stats_map(const interned_stats_map &ism);

  // XXX: Used to identify stat_component_types within BPF code:
  static uint64_t intern_sc_type(stat_component_type sc_type) {
    return (uint64_t)sc_type;
  }
  static stat_component_type deintern_sc_type(uint64_t x) {
    return (stat_component_type)x;
  }

  // To pass stats_map information to the bpf userspace helper,
  // assign each stats_map a numerical 'agg_idx'. Index 0 is reserved
  // for scalar_stats, other stats_maps are given consecutive indices:
  using agg_idx = int;
  std::unordered_map<vardecl *, agg_idx> aggregates;

  // The .bo ELF file will have a section (agg_idx -> interned_stats_map).

  // Index into globals. This element represents the map of internal globals
  // used for sharing data between stapbpf and kernel-side bpf programs.
  static const map_idx internal_map_idx = 0;

  // Indicates whether exit() has been called from within a bpf program.
  struct vardecl internal_exit;

  // Indexes into the bpf map of internal globals.
  enum internal_global_idx
  {
    EXIT = 0,
    NUM_INTERNALS, // non-ABI
  };

  // PR22330: Index into globals. This element represents the
  // perf_event_map used to send messages from kernel-side bpf
  // programs to stapbpf.
  static const map_idx perf_event_map_idx = 1;

  // XXX: The number of elements for the perf_event_map is not known
  // at translation time and must be determined by the stapbpf loader:
  static const int NUM_CPUS_PLACEHOLDER = 0;

  // Types of transport messages supported:
  enum perf_event_type
  {
    STP_EXIT = 0,
    STP_PRINTF_START,
    STP_PRINTF_END,
    STP_PRINTF_FORMAT,
    STP_PRINTF_ARG_LONG,
    STP_PRINTF_ARG_STR,
    // TODO PR23476: Yet more messages to request things such as histogram printing.
  };

  // Converts a string to an index usable in STP_PRINTF_FORMAT messages:
  int intern_string(std::string& str);

  // Interned strings by index:
  std::vector<std::string> interned_strings;

  // The set of already interned strings:
  std::map<std::string, int> interned_str_map;

  // XXX: Hacky, used to resolve function symbols in embedded code:
  systemtap_session *session;
};

} // namespace bpf

#endif // BPF_INTERNAL_H
