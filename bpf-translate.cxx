// bpf translation pass
// Copyright (C) 2016-2019 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "config.h"
#include "bpf-internal.h"
#include "parse.h"
#include "staptree.h"
#include "elaborate.h"
#include "session.h"
#include "translator-output.h"
#include "tapsets.h"
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

extern "C" {
#include <libelf.h>
/* Unfortunately strtab manipulation functions were only officially added
   to elfutils libdw in 0.167.  Before that there were internal unsupported
   ebl variants.  While libebl.h isn't supported we'll try to use it anyway
   if the elfutils we build against is too old.  */
#include <elfutils/version.h>
#if _ELFUTILS_PREREQ (0, 167)
#include <elfutils/libdwelf.h>
typedef Dwelf_Strent Stap_Strent;
typedef Dwelf_Strtab Stap_Strtab;
#define stap_strtab_init      dwelf_strtab_init
#define stap_strtab_add(X,Y)  dwelf_strtab_add(X,Y)
#define stap_strtab_free      dwelf_strtab_free
#define stap_strtab_finalize  dwelf_strtab_finalize
#define stap_strent_offset    dwelf_strent_off
#else
#include <elfutils/libebl.h>
typedef Ebl_Strent Stap_Strent;
typedef Ebl_Strtab Stap_Strtab;
#define stap_strtab_init      ebl_strtabinit
#define stap_strtab_add(X,Y)  ebl_strtabadd(X,Y,0)
#define stap_strtab_free      ebl_strtabfree
#define stap_strtab_finalize  ebl_strtabfinalize
#define stap_strent_offset    ebl_strtaboffset
#endif
#include <linux/version.h>
#include <asm/ptrace.h>
}

// XXX: Required static data and methods from bpf::globals, shared with stapbpf.
#include "bpf-shared-globals.h"

#ifndef EM_BPF
#define EM_BPF  0xeb9f
#endif
#ifndef R_BPF_MAP_FD
#define R_BPF_MAP_FD 1
#endif

std::string module_name;

namespace bpf {

struct side_effects_visitor : public expression_visitor
{
  bool side_effects;

  side_effects_visitor() : side_effects(false) { }

  void visit_expression(expression *) { }
  void visit_pre_crement(pre_crement *) { side_effects = true; }
  void visit_post_crement(post_crement *) { side_effects = true; }
  void visit_assignment (assignment *) { side_effects = true; }
  void visit_functioncall (functioncall *) { side_effects = true; }
  void visit_print_format (print_format *) { side_effects = true; }
  void visit_stat_op (stat_op *) { side_effects = true; }
  void visit_hist_op (hist_op *) { side_effects = true; }
};

struct init_block : public ::block
{
  // This block contains statements that initialize global variables
  // with default values. It should be visited first among any
  // begin probe bodies. Note that initialization of internal globals
  // (ex. the exit status) is handled by the stapbpf runtime.
  init_block(globals &glob);
  ~init_block();
  bool empty() { return this->statements.empty(); }
};

init_block::init_block(globals &glob)
{
  for (auto i = glob.globals.begin(); i != glob.globals.end(); ++i)
    {
      struct vardecl *v = i->first;

      if (v->init && v->type == pe_long)
        {
          struct literal_number *num = static_cast<literal_number *>(v->init);
          struct symbol *sym = new symbol;
          struct assignment *asgn = new assignment;
          struct expr_statement *stmt = new expr_statement;

          sym->referent = v;
          asgn->type = pe_long;
          asgn->op = "=";
          asgn->left = sym;
          asgn->right = num;
          stmt->value = asgn;
          this->statements.push_back(stmt);
        }
    }
}

init_block::~init_block()
{
  for (auto i = this->statements.begin(); i != this->statements.end(); ++i)
    {
      struct expr_statement *stmt = static_cast<expr_statement *>(*i);
      struct assignment *asgn = static_cast<assignment *>(stmt->value);
      struct symbol *sym = static_cast<symbol *>(asgn->left);

      // referent and right are not owned by this.
      sym->referent = NULL;
      asgn->right = NULL;
      delete sym;
      delete asgn;
      delete stmt;
    }
}

static bool
has_side_effects (expression *e)
{
  side_effects_visitor t;
  e->visit (&t);
  return t.side_effects;
}

/* forward declarations */
struct asm_stmt;

struct bpf_unparser : public throwing_visitor
{
  // The visitor class isn't as helpful as it might be.  As a consequence,
  // the RESULT member is set after visiting any expression type.  Use the
  // emit_expr helper to return the result properly.
  value *result;

  // The program into which we are emitting code.
  program &this_prog;
  globals &glob;
  value *this_in_arg0 = NULL;

  // The "current" block into which we are currently emitting code.
  insn_append_inserter this_ins;
  void set_block(block *b)
    { this_ins.b = b; this_ins.i = b->last; }
  void clear_block()
    { this_ins.b = NULL; this_ins.i = NULL; }
  bool in_block() const
    { return this_ins.b != NULL; }

  // Destinations for "break", "continue", and "return" respectively.
  std::vector<block *> loop_break;
  std::vector<block *> loop_cont;
  std::vector<block *> func_return;
  std::vector<value *> func_return_val;
  std::vector<functiondecl *> func_calls;

  // Local variable declarations.
  typedef std::unordered_map<vardecl *, value *> locals_map;
  locals_map *this_locals;

  // Return 0.
  block *ret0_block;
  block *exit_block;
  block *get_ret0_block();
  block *get_exit_block();

  // TODO General triage of bpf-possible functionality:
  virtual void visit_block (::block *s);
  // TODO visit_try_block -> UNHANDLED
  virtual void visit_embeddedcode (embeddedcode *s);
  virtual void visit_null_statement (null_statement *s);
  virtual void visit_expr_statement (expr_statement *s);
  virtual void visit_if_statement (if_statement* s);
  virtual void visit_for_loop (for_loop* s);
  virtual void visit_foreach_loop (foreach_loop* s);
  virtual void visit_return_statement (return_statement* s);
  virtual void visit_delete_statement (delete_statement* s);
  virtual void visit_next_statement (next_statement* s);
  virtual void visit_break_statement (break_statement* s);
  virtual void visit_continue_statement (continue_statement* s);
  virtual void visit_literal_string (literal_string *e);
  virtual void visit_literal_number (literal_number* e);
  // TODO visit_embedded_expr -> UNHANDLED, could treat as embedded_code
  virtual void visit_binary_expression (binary_expression* e);
  virtual void visit_unary_expression (unary_expression* e);
  virtual void visit_pre_crement (pre_crement* e);
  virtual void visit_post_crement (post_crement* e);
  virtual void visit_logical_or_expr (logical_or_expr* e);
  virtual void visit_logical_and_expr (logical_and_expr* e);
  virtual void visit_array_in (array_in* e);
  // ??? visit_regex_query -> UNHANDLED, requires new kernel functionality
  virtual void visit_compound_expression (compound_expression *e);
  virtual void visit_comparison (comparison* e);
  // TODO visit_concatenation for kernel probes -> (2) pseudo-LOOP: copy the 
  // strings while concatenating
  virtual void visit_concatenation (concatenation* e);
  virtual void visit_ternary_expression (ternary_expression* e);
  virtual void visit_assignment (assignment* e);
  virtual void visit_symbol (symbol* e);
  virtual void visit_target_register (target_register* e);
  virtual void visit_target_deref (target_deref* e);
  // visit_target_bitfield -> ?? should already be handled in earlier pass?
  // visit_target_symbol -> ?? should already be handled in earlier pass
  virtual void visit_arrayindex (arrayindex *e);
  virtual void visit_functioncall (functioncall* e);
  virtual void visit_print_format (print_format* e);
  virtual void visit_stat_op (stat_op* e);
  virtual void visit_hist_op (hist_op* e);
  // visit_atvar_op -> ?? should already be handled in earlier pass
  // visit_cast_op -> ?? should already be handled in earlier pass
  // visit_autocast_op -> ?? should already be handled in earlier pass
  // visit_defined_op -> ?? should already be handled in earlier pass
  // visit_entry_op -> ?? should already be handled in earlier pass
  // visit_perf_op -> ?? should already be handled in earlier pass

  // TODO: Other bpf functionality to take advantage of in tapsets, or as alternate implementations:
  // - backtrace.stp :: BPF_MAP_TYPE_STACKTRACE + bpf_getstackid
  // - BPF_MAP_TYPE_LRU_HASH :: for size-limited maps
  // - BPF_MAP_GET_NEXT_KEY :: for user-space iteration through maps
  // see https://ferrisellis.com/posts/ebpf_syscall_and_maps/#ebpf-map-types

  void emit_stmt(statement *s);
  void emit_mov(value *d, value *s);
  void emit_jmp(block *b);
  void emit_cond(expression *e, block *t, block *f);
  void emit_statmap_lookup(value *dest, globals::map_idx map_id, value *idx);
  void emit_statmap_update(globals::map_idx map_id, value *idx,
                           int idx_ofs, value *val);
  void emit_aggregation(vardecl *var, globals::map_slot& g, value *val,
                        value *idx = NULL, int idx_ofs = 0);
  void emit_store(expression *dest, value *src);
  value *emit_expr(expression *e);
  value *emit_bool(expression *e);
  value *emit_context_var(bpf_context_vardecl *v);

  void emit_transport_msg(globals::perf_event_type msg,
                          value *arg = NULL, exp_type format_type = pe_unknown);
  value *emit_functioncall(functiondecl *f, const std::vector<value *> &args);
  value *emit_print_format(const std::string &format,
                           const std::vector<value *> &actual,
                           bool print_to_stream = true,
                           const token *tok = NULL);

  // Used for the embedded-code assembler:
  int64_t parse_imm (const asm_stmt &stmt, const std::string &str);
  size_t parse_asm_stmt (embeddedcode *s, size_t start,
                           /*OUT*/asm_stmt &stmt);
  value *emit_asm_arg(const asm_stmt &stmt, const std::string &arg,
                      bool allow_imm = true, bool allow_emit = true);
  value *emit_asm_reg(const asm_stmt &stmt, const std::string &reg);
  value *get_asm_reg(const asm_stmt &stmt, const std::string &reg);
  void emit_asm_opcode(const asm_stmt &stmt,
                       std::map<std::string, block *> label_map);

  // Used for the embedded-code assembler's diagnostics:
  source_loc adjusted_loc;
  size_t adjust_pos;
  std::vector<token *> adjusted_toks; // track for deallocation

  // Used for string data:
  value *emit_literal_string(const std::string &str, const token *tok);
  value *emit_string_copy(value *dest, int ofs, value *src, bool zero_pad = false);

  // Used for passing long and string arguments on the stack where an address is expected:
  void emit_long_arg(value *arg, int ofs, value *val);
  void emit_str_arg(value *arg, int ofs, value *str);

  void add_prologue();
  locals_map *new_locals(const std::vector<vardecl *> &);

  bpf_unparser (program &c, globals &g);
  virtual ~bpf_unparser ();
};

bpf_unparser::bpf_unparser(program &p, globals &g)
  : throwing_visitor ("unhandled statement or expression type"),
    result(NULL), this_prog(p), glob(g), this_locals(NULL),
    ret0_block(NULL), exit_block(NULL)
{ }

bpf_unparser::~bpf_unparser()
{
  delete this_locals;
}

bpf_unparser::locals_map *
bpf_unparser::new_locals(const std::vector<vardecl *> &vars)
{
  locals_map *m = new locals_map;

  for (std::vector<vardecl *>::const_iterator i = vars.begin ();
       i != vars.end (); ++i)
    {
      const locals_map::value_type v (*i, this_prog.new_reg());
      auto ok = m->insert (v);
      assert (ok.second);
    }

  return m;
}

block *
bpf_unparser::get_exit_block()
{
  if (exit_block)
    return exit_block;

  block *b = this_prog.new_block();
  insn_append_inserter ins(b, "exit_block");

  this_prog.mk_exit(ins);

  exit_block = b;
  return b;
}

block *
bpf_unparser::get_ret0_block()
{
  if (ret0_block)
    return ret0_block;

  block *b = this_prog.new_block();
  insn_append_inserter ins(b, "ret0_block");

  this_prog.mk_mov(ins, this_prog.lookup_reg(BPF_REG_0), this_prog.new_imm(0));
  b->fallthru = new edge(b, get_exit_block());

  ret0_block = b;
  return b;
}

void
bpf_unparser::emit_stmt(statement *s)
{
  if (s)
    s->visit (this);
}

value *
bpf_unparser::emit_expr(expression *e)
{
  e->visit (this);
  value *v = result;
  result = NULL;
  return v;
}

void
bpf_unparser::emit_mov(value *d, value *s)
{
  this_prog.mk_mov(this_ins, d, s);
}

void
bpf_unparser::emit_jmp(block *b)
{
  // Begin by hoping that we can simply place the destination as fallthru.
  // If this assumption doesn't hold, it'll be fixed by reorder_blocks.
  block *this_block = this_ins.get_block ();
  this_block->fallthru = new edge(this_block, b);
  clear_block ();
}

void
bpf_unparser::emit_cond(expression *e, block *t_dest, block *f_dest)
{
  condition cond;
  value *s0, *s1;

  // Look for and handle logical operators first.
  if (logical_or_expr *l = dynamic_cast<logical_or_expr *>(e))
    {
      block *cont_block = this_prog.new_block ();
      emit_cond (l->left, t_dest, cont_block);
      set_block (cont_block);
      emit_cond (l->right, t_dest, f_dest);
      return;
    }
  if (logical_and_expr *l = dynamic_cast<logical_and_expr *>(e))
    {
      block *cont_block = this_prog.new_block ();
      emit_cond (l->left, cont_block, f_dest);
      set_block (cont_block);
      emit_cond (l->right, t_dest, f_dest);
      return;
    }
  if (unary_expression *u = dynamic_cast<unary_expression *>(e))
    if (u->op == "!")
      {
	emit_cond (u->operand, f_dest, t_dest);
	return;
      }

  // What is left must generate a comparison + conditional branch.
  if (comparison *c = dynamic_cast<comparison *>(e))
    {
      s0 = emit_expr (c->left);
      s1 = emit_expr (c->right);
      if (c->op == "==")
	cond = EQ;
      else if (c->op == "!=")
	cond = NE;
      else if (c->op == "<")
	cond = LT;
      else if (c->op == "<=")
	cond = LE;
      else if (c->op == ">")
	cond = GT;
      else if (c->op == ">=")
	cond = GE;
      else
	throw SEMANTIC_ERROR (_("unhandled comparison operator"), e->tok);
    }
  else
    {
      binary_expression *bin = dynamic_cast<binary_expression *>(e);
      if (bin && bin->op == "&")
	{
	  s0 = emit_expr (bin->left);
	  s1 = emit_expr (bin->right);
	  cond = TEST;
	}
      else
	{
	  // Fall back to E != 0.
	  s0 = emit_expr (e);
	  s1 = this_prog.new_imm(0);
	  cond = NE;
	}
    }

  this_prog.mk_jcond (this_ins, cond, s0, s1, t_dest, f_dest);
  clear_block ();
}

value *
bpf_unparser::emit_bool (expression *e)
{
  block *else_block = this_prog.new_block ();
  block *join_block = this_prog.new_block ();
  value *r = this_prog.new_reg();

  emit_mov (r, this_prog.new_imm(1));
  emit_cond (e, join_block, else_block);

  set_block (else_block);
  emit_mov (r, this_prog.new_imm(0));
  emit_jmp (join_block);

  set_block(join_block);
  return r;
}

/* PR23476: Helpers for loading/storing long values in a stat field map.
   Several of these map operations are issued for each stats operation,
   so we avoid code duplication by taking an index already on the stack.

   ??? These helpers could be used in other contexts than just stats. */

void
bpf_unparser::emit_statmap_lookup(value *dest, globals::map_idx map_id, value *idx)
{
  this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1), map_id);
  emit_mov(this_prog.lookup_reg(BPF_REG_2), idx); // XXX idx stored by caller
  this_prog.mk_call(this_ins, BPF_FUNC_map_lookup_elem, 2);

  // Check for null pointer:
  value *r0 = this_prog.lookup_reg(BPF_REG_0);
  value *i0 = this_prog.new_imm(0);
  block *cont_block = this_prog.new_block();
  block *join_block = this_prog.new_block();

  emit_mov(dest, i0); // default to a result of 0
  this_prog.mk_jcond(this_ins, EQ, r0, i0, join_block, cont_block);

  set_block(cont_block);
  this_prog.mk_ld(this_ins, BPF_DW, dest, r0, 0);
  emit_jmp(join_block);

  set_block(join_block);
}

void
bpf_unparser::emit_statmap_update(globals::map_idx map_id, value *idx,
                                  int idx_ofs, value *val)
{
  int val_ofs = idx_ofs - 8;
  if ((-val_ofs) % 8 != 0) // align to double-word
    val_ofs -= 8 - (-val_ofs) % 8;
  this_prog.use_tmp_space(-val_ofs);
  this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1), map_id);
  emit_mov(this_prog.lookup_reg(BPF_REG_2), idx); // XXX idx stored by caller
  emit_long_arg(this_prog.lookup_reg(BPF_REG_3), val_ofs, val);
  emit_mov(this_prog.lookup_reg(BPF_REG_4), this_prog.new_imm(0)); // TODO
  this_prog.mk_call(this_ins, BPF_FUNC_map_update_elem, 4);
}

// XXX Based on __stap_stat_add in runtime/stat-common.c.
// There might be a clever way to avoid code duplication later,
// but right now the code format is too different. Just reimplement.
void
bpf_unparser::emit_aggregation(vardecl *var, globals::map_slot& ms,
                               value *val, value *idx, int idx_ofs)
{
#ifdef DEBUG_CODEGEN
  this_ins.notes.push("agg");
#endif

  // Obtain the correct stats_map and index:
  assert (ms.is_stat());
  globals::stats_map sd;
  if (var->arity == 0)
    {
      assert (ms.is_scalar() && idx == NULL);

      sd = glob.scalar_stats;

      // idx is an offset into scalar stat field maps, store on the stack
      value *frame = this_prog.lookup_reg(BPF_REG_10);
      idx_ofs = -4; // BPF_W
      this_prog.mk_st(this_ins, BPF_W, frame, idx_ofs,
                      this_prog.new_imm(ms.idx));
      this_prog.use_tmp_space(-idx_ofs);

      idx = this_prog.new_reg();
      this_prog.mk_binary(this_ins, BPF_ADD, idx,
                          frame, this_prog.new_imm(idx_ofs));
    }
  else // var->arity > 0
    {
      assert (!ms.is_scalar());
      assert (var->arity > 0 && idx != NULL);

      auto it = glob.array_stats.find(var);
      assert (it != glob.array_stats.end()); // XXX: should check earlier
      sd = it->second;

      // idx is a value stored on the stack
    }

  for (auto f : globals::stat_fields)
    assert(sd.find(f) != sd.end());

  // TODO PR23476: Emit simplified code for now.
  //
  // ??? lock stat
  // if (idx not in sd[stat_iter_field] || sd->count == 0) {
  //   sd->count = 1;
  //   sd->sum = val;
  // } else {
  //   if(stat_op_count) sd->count++;
  //   if(stat_op_sum) sd->sum += val;
  // }
  // ??? unlock stat

  block *then_block = this_prog.new_block ();
  block *else_block = this_prog.new_block ();
  block *join_block = this_prog.new_block ();

  value *tmp = this_prog.new_reg();

  emit_statmap_lookup(tmp, sd["count"], idx);
  this_prog.mk_jcond (this_ins, EQ, tmp, this_prog.new_imm(0),
                      then_block, else_block);

  set_block (then_block);
  emit_statmap_update(sd["count"], idx, idx_ofs, this_prog.new_imm(1));
  emit_statmap_update(sd["sum"], idx, idx_ofs, val);
  emit_jmp (join_block);

  set_block (else_block);
  if (1) // TODO: if (stat_op_count)
    {
      emit_statmap_lookup(tmp, sd["count"], idx);
      this_prog.mk_binary(this_ins, BPF_ADD, tmp, tmp, this_prog.new_imm(1));
      emit_statmap_update(sd["count"], idx, idx_ofs, tmp);
    }
  if (1) // TODO: if (stat_op_sum)
    {
      emit_statmap_lookup(tmp, sd["sum"], idx);
      this_prog.mk_binary(this_ins, BPF_ADD, tmp, tmp, val);
      emit_statmap_update(sd["sum"], idx, idx_ofs, tmp);
    }
  emit_jmp (join_block);

  set_block(join_block);

#ifdef DEBUG_CODEGEN
  this_ins.notes.pop();
#endif
}

void
bpf_unparser::emit_store(expression *e, value *val)
{
  if (symbol *s = dynamic_cast<symbol *>(e)) // scalar lvalue
    {
      vardecl *var = s->referent;
      assert (var->arity == 0);

      auto g = glob.globals.find (var);
      if (g != glob.globals.end())
	{
	  value *frame = this_prog.lookup_reg(BPF_REG_10);
	  int key_ofs, val_ofs;

          // BPF_FUNC_map_update_elem will dereference the address
          // passed in BPF_REG_3:
	  switch (var->type)
	    {
	    case pe_long:
	      // Store the long on the stack and pass its address:
	      val_ofs = -8;
	      emit_long_arg(this_prog.lookup_reg(BPF_REG_3), val_ofs, val);
	      break;
            case pe_string:
              // Zero-pad and copy the string to the stack and pass its address:
              val_ofs = -BPF_MAXSTRINGLEN;
              emit_str_arg(this_prog.lookup_reg(BPF_REG_3), val_ofs, val);
              this_prog.use_tmp_space(BPF_MAXSTRINGLEN);
              break;

            case pe_stats:
              // Emit separate code to update stat fields:
              emit_aggregation(var, g->second, val);
              return;

	    default:
	      goto err;
	    }

	  key_ofs = val_ofs - 4;
	  this_prog.mk_st(this_ins, BPF_W, frame, key_ofs,
			  this_prog.new_imm(g->second.idx));
	  this_prog.use_tmp_space(-key_ofs);

          // XXX g->second.is_stat() handled above
	  this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1),
			     g->second.map_id);
	  this_prog.mk_binary(this_ins, BPF_ADD,
			      this_prog.lookup_reg(BPF_REG_2),
			      frame, this_prog.new_imm(key_ofs));
	  emit_mov(this_prog.lookup_reg(BPF_REG_4), this_prog.new_imm(0));
	  this_prog.mk_call(this_ins, BPF_FUNC_map_update_elem, 4);
	  return;
	}

      auto i = this_locals->find (var);
      if (i != this_locals->end ())
	{
	  emit_mov (i->second, val);
	  return;
	}
    }
  else if (arrayindex *a = dynamic_cast<arrayindex *>(e)) // array lvalue
    {
      if (symbol *a_sym = dynamic_cast<symbol *>(a->base))
	{
	  vardecl *v = a_sym->referent;
	  int key_ofs = 0, val_ofs;

	  auto g = glob.globals.find(v);
	  if (g == glob.globals.end())
	    throw SEMANTIC_ERROR(_("unknown array variable"), v->tok);

	  unsigned element = v->arity;

	  // iterate over the elements
	  do {
	    --element;
	    value *idx = emit_expr(a->indexes[element]);
	    switch (v->index_types[element])
	      {
	      case pe_long:
                // Store the long on the stack and pass its address:
                key_ofs -= 8;
                emit_long_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
                break;
              case pe_string:
                // Zero-pad and copy the string to the stack and pass its address:
                key_ofs -= BPF_MAXSTRINGLEN;
                emit_str_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
                break;
	      default:
	        throw SEMANTIC_ERROR(_("unhandled index type"), e->tok);
	     }
	  } while (element);
	  switch (v->type)
	    {
	    case pe_long:
	      // Store the long on the stack and pass its address:
	      val_ofs = key_ofs - 8;
	      emit_long_arg(this_prog.lookup_reg(BPF_REG_3), val_ofs, val);
	      break;
            case pe_string:
              // Zero-pad and copy the string to the stack and pass its address:
              val_ofs = key_ofs - BPF_MAXSTRINGLEN;
              emit_str_arg(this_prog.lookup_reg(BPF_REG_3), val_ofs, val);
              this_prog.use_tmp_space(BPF_MAXSTRINGLEN);
              break;
            case pe_stats:
              // Emit separate code to update stat fields:
              {
                value *idx = this_prog.new_reg();
                value *frame = this_prog.lookup_reg(BPF_REG_10);
                this_prog.mk_binary(this_ins, BPF_ADD, idx,
                                    frame, this_prog.new_imm(key_ofs));
                this_prog.use_tmp_space(-key_ofs);
                emit_aggregation(v, g->second, val, idx, key_ofs);
              }
              return;
	    default:
	      throw SEMANTIC_ERROR(_("unhandled array type"), v->tok);
	    }

          this_prog.use_tmp_space(-val_ofs);
          // XXX g->second.is_stat() handled above
	  this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1),
			     g->second.map_id);
          emit_mov(this_prog.lookup_reg(BPF_REG_4), this_prog.new_imm(0));
	  this_prog.mk_call(this_ins, BPF_FUNC_map_update_elem, 4);
	  return;
        } 
    } 
 err:
  throw SEMANTIC_ERROR (_("unknown lvalue"), e->tok);
}

void
bpf_unparser::visit_block (::block *s)
{
  unsigned n = s->statements.size();
  for (unsigned i = 0; i < n; ++i)
    emit_stmt (s->statements[i]);
}

/* WORK IN PROGRESS: A simple eBPF assembler.

   In order to effectively write eBPF tapset functions, we want to use
   embedded-code assembly rather than compile from SystemTap code. At
   the same time, we want to hook into stapbpf functionality to
   reserve stack memory, allocate virtual registers or signal errors.

   The assembler syntax will probably take a couple of attempts to get
   just right. This attempt keeps things as close as possible to the
   first embedded-code assembler, with a few more features and a
   disgustingly lenient parser that allows things like
     $ this is        all one "**identifier**" believe-it!-or-not

   Ahh for the days of 1960s FORTRAN.

   ??? It might make more sense to implement an assembler based on
   the syntax used in official eBPF subsystem docs. */

/* Supported assembly statement types include:

   <stmt> ::= label, <dest=label>;
   <stmt> ::= alloc, <dest=reg>, <imm=imm> [, align|noalign];
   <stmt> ::= call, <dest=optreg>, <param[0]=function name>, <param[1]=arg>, ...;
   <stmt> ::= <code=integer opcode>, <dest=reg>, <src1=reg>,
              <off/jmp_target=off>, <imm=imm>;

   Supported argument types include:

   <arg>    ::= <reg> | <imm>
   <optreg> ::= <reg> | -
   <reg>    ::= <register index> | r<register index> | $ctx
                $<identifier> | $<integer constant> | $$ | <string constant>
   <imm>    ::= <integer constant> | BPF_MAXSTRINGLEN | BPF_F_CURRENT_CPU | -
   <off>    ::= <imm> | <jump label>

*/

// #define BPF_ASM_DEBUG

struct asm_stmt {
  std::string kind;

  unsigned code;
  std::string dest, src1;
  int64_t off, imm;

  // metadata for jmp instructions
  // ??? The logic around these flags could be pruned a bit.
  bool has_jmp_target = false;
  bool has_fallthrough = false;
  std::string jmp_target, fallthrough;

  // metadata for call, error instructions
  std::vector<std::string> params;

  // metadata for alloc instructions
  bool align_alloc;

  token *tok;
};

std::ostream&
operator << (std::ostream& o, const asm_stmt& stmt)
{
  if (stmt.kind == "label")
    o << "label, " << stmt.dest << ";";
  else if (stmt.kind == "opcode")
    {
      o << std::hex << stmt.code << ", "
        << stmt.dest << ", "
        << stmt.src1 << ", ";
      if (stmt.off != 0 || stmt.jmp_target == "")
        o << stmt.off;
      else if (stmt.off != 0) // && stmt.jmp_target != ""
        o << stmt.off << "/";
      if (stmt.jmp_target != "")
        o << "label:" << stmt.jmp_target;
      o << ", "
        << stmt.imm << ";"
        << (stmt.has_fallthrough ? " +FALLTHROUGH " + stmt.fallthrough : "");
    }
  else if (stmt.kind == "alloc")
    {
      o << "alloc, " << stmt.dest << ", " << stmt.imm << ";";
    }
  else if (stmt.kind == "call")
    {
      o << "call, " << stmt.dest << ", ";
      for (unsigned k = 0; k < stmt.params.size(); k++)
        {
          o << stmt.params[k];
          o << (k >= stmt.params.size() - 1 ? ";" : ", ");
        }
    }
  else
    o << "<unknown asm_stmt kind '" << stmt.kind << "'>";
  return o;
}

bool
is_numeric (const std::string &str)
{
  size_t pos = 0;
  try {
    stol(str, &pos, 0);
  } catch (const std::invalid_argument &e) {
    return false;
  } catch (const std::out_of_range &e) {
    /* XXX: probably numeric but not valid; give up */
    return false;
  } catch (...) {
    /* XXX: handle other errors the same way */
    std::cerr << "BUG: bpf assembler -- is_numeric() saw unexpected exception" << std::endl;
    return false;
  }
  return (pos == str.size());
}

int64_t
bpf_unparser::parse_imm (const asm_stmt &stmt, const std::string &str)
{
  int64_t val;
  if (str == "BPF_MAXSTRINGLEN")
    val = BPF_MAXSTRINGLEN;
  else if (str == "BPF_F_CURRENT_CPU")
    val = BPF_F_CURRENT_CPU;
  else if (str == "-")
    val = 0;
  else try {
      val = stol(str);
    } catch (std::exception &e) { // XXX: invalid_argument, out_of_range
      throw SEMANTIC_ERROR (_F("invalid bpf embeddedcode operand '%s'",
                               str.c_str()), stmt.tok);
    }
  return val;
}

/* Parse an assembly statement starting from position start in code,
   then write the output in stmt. Returns a position immediately after
   the parsed statement. */
size_t
bpf_unparser::parse_asm_stmt (embeddedcode *s, size_t start,
                              /*OUT*/asm_stmt &stmt)
{
  const interned_string &code = s->code;

 retry:
  std::vector<std::string> args;
  unsigned n = code.size();
  size_t pos;
  bool in_comment = false;
  bool in_string = false;

  // ??? As before, parser is extremely non-rigorous and could do
  // with some tightening in terms of the inputs it accepts.
  std::string arg = "";
  size_t save_start = start; // -- position for diagnostics
  for (pos = start; pos < n; pos++)
  {
    char c = code[pos];
    char c2 = pos + 1 < n ? code [pos + 1] : 0;
    if (isspace(c) && !in_string)
      continue; // skip
    else if (in_comment)
      {
        if (c == '*' && c2 == '/')
          ++pos, in_comment = false;
        // else skip
      }
    else if (in_string)
      {
        // resulting string will be processed by translate_escapes()
        if (c == '"')
          arg.push_back(c), in_string = false; // include quote
        else if (c == '\\' && c2 == '"')
          ++pos, arg.push_back(c), arg.push_back(c2);
        else // accept any char, including whitespace
          arg.push_back(c);
      }
    else if (c == '/' && c2 == '*')
      ++pos, in_comment = true;
    else if (c == '"') // found a literal string
      {
        if (arg.empty() && args.empty())
          save_start = pos; // start of first argument

        // XXX: This allows '"' inside an arg and will treat the
        // string as a sequence of weird identifier characters.  A
        // more rigorous parser would error on mixing strings and
        // regular chars.
        arg.push_back(c); // include quote
        in_string = true;
      }
    else if (c == ',') // reached end of argument
      {
        // XXX: This strips out empty args. A more rigorous parser would error.
        if (arg != "")
          args.push_back(arg);
        arg = "";
      }
    else if (c == ';') // reached end of statement
      {
        // XXX: This strips out empty args. A more rigorous parser would error.
        if (arg != "")
          args.push_back(arg);
        arg = "";
        pos++; break;
      }
    else // found (we assume) a regular char
      {
        if (arg.empty() && args.empty())
          save_start = pos; // start of first argument

        // XXX: As before, this strips whitespace within args
        // (so '$ab', '$ a b' and '$a b' are equivalent).
        //
        // A more rigorous parser would track in_arg
        // and after_arg states and error on whitespace within args.
        arg.push_back(c);
      }
  }
  // final ';' is optional, so we watch for a trailing arg:
  if (arg != "") args.push_back(arg);

  // handle the case with no args
  if (args.empty() && pos >= n)
    return std::string::npos; // finished parsing
  else if (args.empty())
    {
      // XXX: This skips an empty statement.
      // A more rigorous parser would error.
      start = pos;
      goto retry;
    }

  // compute token with adjusted source location for diagnostics
  // TODO: needs some attention to how multiline tokens are printed in error reporting -- with this code, caret aligns incorrectly
  for (/* use saved adjust_pos */; adjust_pos < save_start && adjust_pos < n; adjust_pos++)
    {
      char c = code[adjust_pos];
      if (c == '\n')
        {
          adjusted_loc.line++;
          adjusted_loc.column = 1;
        }
      else
        adjusted_loc.column++;
    }

  // Now populate the statement data.

  stmt = asm_stmt(); // clear pre-existing data

  // set token with adjusted source location
  stmt.tok = s->tok->adjust_location(adjusted_loc);
  adjusted_toks.push_back(stmt.tok);

#ifdef BPF_ASM_DEBUG
  std::cerr << "bpf_asm parse_asm_stmt: tokenizer got ";
  for (unsigned k = 0; k < args.size(); k++)
    std::cerr << args[k] << ", ";
  std::cerr << std::endl;
#endif
  if (args[0] == "label")
    {
      if (args.size() != 2)
        throw SEMANTIC_ERROR (_F("invalid bpf embeddedcode syntax (label expects 1 arg, found %llu)", (long long) args.size()-1), stmt.tok);
      stmt.kind = args[0];
      stmt.dest = args[1];
    }
  else if (args[0] == "alloc")
    {
      if (args.size() != 3 && args.size() != 4)
        throw SEMANTIC_ERROR (_F("invalid bpf embeddedcode syntax (alloc expects 2 or 3 args, found %llu)", (long long) args.size()-1), stmt.tok);
      stmt.kind = args[0];
      stmt.dest = args[1];
      stmt.imm = parse_imm(stmt, args[2]);

      // handle align, noalign options
      if (args.size() == 4 && args[3] == "align")
        {
          stmt.align_alloc = true;
        }
      else if (args.size() == 4 && args[3] == "noalign")
        {
          stmt.align_alloc = false;
        }
      else if (args.size() == 4)
        throw SEMANTIC_ERROR (_F("invalid bpf embeddedcode syntax (alloc expects 'align' or 'noalign' as 3rd arg, found '%s'", args[3].c_str()), stmt.tok);
      else
        {
          stmt.align_alloc = false;
        }
    }
  else if (args[0] == "call")
    {
      if (args.size() < 3)
        throw SEMANTIC_ERROR (_F("invalid bpf embeddedcode syntax (call expects at least 2 args, found %llu)", (long long) args.size()-1), stmt.tok);
      stmt.kind = args[0];
      stmt.dest = args[1];
      assert(stmt.params.empty());
      for (unsigned k = 2; k < args.size(); k++)
        stmt.params.push_back(args[k]);
    }
  else if (is_numeric(args[0]))
    {
      if (args.size() != 5)
        throw SEMANTIC_ERROR (_F("invalid bpf embeddedcode syntax (opcode expects 4 args, found %llu)", (long long) args.size()-1), stmt.tok);
      stmt.kind = "opcode";
      try {
        stmt.code = stoul(args[0], 0, 0);
      } catch (std::exception &e) { // XXX: invalid_argument, out_of_range
        throw SEMANTIC_ERROR (_F("invalid bpf embeddedcode opcode '%s'",
                                 args[0].c_str()), stmt.tok);
      }
      stmt.dest = args[1];
      stmt.src1 = args[2];

      stmt.has_jmp_target =
        BPF_CLASS(stmt.code) == BPF_JMP
        && BPF_OP(stmt.code) != BPF_EXIT
        && BPF_OP(stmt.code) != BPF_CALL;
      stmt.has_fallthrough = // only for jcond
        stmt.has_jmp_target
        && BPF_OP(stmt.code) != BPF_JA;
      // XXX: stmt.fallthrough is computed by visit_embeddedcode

      if (stmt.has_jmp_target)
        {
          stmt.off = 0;
          stmt.jmp_target = args[3];
        }
      else
        stmt.off = parse_imm(stmt, args[3]);

      stmt.imm = parse_imm(stmt, args[4]);
    }
  else
    throw SEMANTIC_ERROR (_F("unknown bpf embeddedcode operator '%s'",
                             args[0].c_str()), stmt.tok);

  // we returned one statement, there may be more parsing to be done
  return pos;
}

/* forward declaration */
std::string translate_escapes (const interned_string &str, const token* tok);

/* Convert a <reg> or <imm> operand to a value.
   May emit code to store a string constant on the stack. */
value *
bpf_unparser::emit_asm_arg (const asm_stmt &stmt, const std::string &arg,
                            bool allow_imm, bool allow_emit)
{
  if (arg == "$$")
    {
      /* arg is a return value */
      if (func_return.empty())
        throw SEMANTIC_ERROR (_("no return value outside function"), stmt.tok);
      return func_return_val.back();
    }
  else if (arg == "$ctx")
    {
      /* provide the context where available */
      return this_in_arg0 ? this_in_arg0 : this_prog.new_imm(0x0);
    }
  else if (arg[0] == '$')
    {
      /* assume arg is a variable */
      std::string var = arg.substr(1);
      for (auto i = this_locals->begin(); i != this_locals->end(); ++i)
	{
	  vardecl *v = i->first;
	  if (var == v->unmangled_name)
	    return i->second;
	}

      /* if it's an unknown variable, allocate a temporary */
      struct vardecl *vd = new vardecl;
      vd->name = "__bpfasm__local_" + var;
      vd->unmangled_name = var;
      vd->type = pe_long;
      vd->arity = 0;
      value *reg = this_prog.new_reg();
      const locals_map::value_type v (vd, reg);
      auto ok = this_locals->insert (v);
      assert (ok.second);
      return reg;
    }
  else if (is_numeric(arg) && allow_imm)
    {
      /* arg is an immediate constant */
      long imm = stol(arg, 0, 0);
      return this_prog.new_imm(imm);
    }
  else if (is_numeric(arg) || arg[0] == 'r')
    {
      /* arg is a register number */
      std::string reg = arg[0] == 'r' ? arg.substr(1) : arg;
      unsigned long num;
      bool parsed = false;
      try {
        num = stoul(reg, 0, 0);
        parsed = true;
      } catch (std::exception &e) {} // XXX: invalid_argument, out_of_range
      if (!parsed || num > 10)
	throw SEMANTIC_ERROR (_F("invalid bpf register '%s'",
                                 arg.c_str()), stmt.tok);
      return this_prog.lookup_reg(num);
    }
  else if (arg[0] == '"')
    {
      if (!allow_emit)
        throw SEMANTIC_ERROR (_F("invalid bpf argument %s "
                                 "(string literal not allowed here)",
                                 arg.c_str()), stmt.tok);

      /* arg is a string constant */
      if (arg[arg.size() - 1] != '"')
        throw SEMANTIC_ERROR (_F("BUG: improper string %s",
                                 arg.c_str()), stmt.tok);
      std::string escaped_str = arg.substr(1,arg.size()-2); /* strip quotes */
      std::string str = translate_escapes(escaped_str, stmt.tok);
      return emit_literal_string(str, stmt.tok);
    }
  else if (arg == "BPF_MAXSTRINGLEN" || arg == "BPF_F_CURRENT_CPU")
    {
      /* arg is a system constant */
      if (!allow_imm)
        throw SEMANTIC_ERROR (_F("invalid bpf register '%s'",
                                 arg.c_str()), stmt.tok);
      if (arg == "BPF_MAXSTRINGLEN")
        return this_prog.new_imm(BPF_MAXSTRINGLEN);
      else // arg == "BPF_F_CURRENT_CPU"
        return this_prog.new_imm(BPF_F_CURRENT_CPU);
    }
  else if (arg == "-")
    {
      /* arg is null a.k.a '0' */
      if (!allow_imm)
        throw SEMANTIC_ERROR (_F("invalid bpf register '%s'",
                                 arg.c_str()), stmt.tok);
      return this_prog.new_imm(0);
    }
  else if (allow_imm)
    throw SEMANTIC_ERROR (_F("invalid bpf argument '%s'",
                             arg.c_str()), stmt.tok);
  else
    throw SEMANTIC_ERROR (_F("invalid bpf register '%s'",
                             arg.c_str()), stmt.tok);

}

/* As above, but don't accept immediate values.
   Do accept string constants (since they're stored in a register). */
value *
bpf_unparser::emit_asm_reg (const asm_stmt &stmt, const std::string &reg)
{
  return emit_asm_arg(stmt, reg, /*allow_imm=*/false);
}

/* As above, but don't allow string constants or anything that emits code.
   Useful if the context requires an lvalue. */
value *
bpf_unparser::get_asm_reg (const asm_stmt &stmt, const std::string &reg)
{
  return emit_asm_arg(stmt, reg, /*allow_imm=*/false, /*allow_emit=*/false);
}

void
bpf_unparser::emit_asm_opcode (const asm_stmt &stmt,
                               std::map<std::string, block *> label_map)
{
  if (stmt.code > 0xff && stmt.code != BPF_LD_MAP)
    throw SEMANTIC_ERROR (_("invalid bpf code"), stmt.tok);

  bool r_dest = false, r_src0 = false, r_src1 = false, i_src1 = false;
  bool op_jmp = false, op_jcond = false;
  condition c = EQ; // <- quiet a compiler warning about uninitialized c
  switch (BPF_CLASS (stmt.code))
    {
    case BPF_LDX:
      r_dest = r_src1 = true;
      break;
    case BPF_STX:
      r_src0 = r_src1 = true;
      break;
    case BPF_ST:
      r_src0 = i_src1 = true;
      break;

    case BPF_ALU:
    case BPF_ALU64:
      r_dest = true;
      if (stmt.code & BPF_X)
        r_src1 = true;
      else
        i_src1 = true;
      switch (BPF_OP (stmt.code))
        {
        case BPF_NEG:
        case BPF_MOV:
          break;
        case BPF_END:
          /* X/K bit repurposed as LE/BE.  */
          i_src1 = false, r_src1 = true;
          break;
        default:
          r_src0 = true;
        }
      break;

    case BPF_JMP:
      switch (BPF_OP (stmt.code))
        {
        case BPF_EXIT:
          // no special treatment needed
          break;
        case BPF_CALL:
          i_src1 = true;
          break;
        case BPF_JA:
          op_jmp = true;
          break;
        default:
          // XXX: assume this is a jcond op
          op_jcond = true;
          r_src0 = true;
          if (stmt.code & BPF_X)
            r_src1 = true;
          else
            i_src1 = true;
        }

      // compute jump condition c
      switch (BPF_OP (stmt.code))
        {
        case BPF_JEQ: c = EQ; break;
        case BPF_JNE: c = NE; break;
        case BPF_JGT: c = GTU; break;
        case BPF_JGE: c = GEU; break;
        case BPF_JLT: c = LTU; break;
        case BPF_JLE: c = LEU; break;
        case BPF_JSGT: c = GT; break;
        case BPF_JSGE: c = GE; break;
        case BPF_JSLT: c = LT; break;
        case BPF_JSLE: c = LE; break;
        case BPF_JSET: c = TEST; break;
        default:
          if (op_jcond)
            throw SEMANTIC_ERROR (_("invalid branch in bpf code"), stmt.tok);
        }
      break;

    default:
      if (stmt.code == BPF_LD_MAP)
        r_dest = true, i_src1 = true;
      else
        throw SEMANTIC_ERROR (_F("unknown opcode '%d' in bpf code",
                                stmt.code), stmt.tok);
    }

  value *v_dest = NULL;
  if (r_dest || r_src0)
    v_dest = get_asm_reg(stmt, stmt.dest);
  else if (stmt.dest != "0" && stmt.dest != "-")
    throw SEMANTIC_ERROR (_F("invalid register field '%s' in bpf code",
                             stmt.dest.c_str()), stmt.tok);

  value *v_src1 = NULL;
  if (r_src1)
    v_src1 = emit_asm_reg(stmt, stmt.src1);
  else
    {
      if (stmt.src1 != "0" && stmt.src1 != "-")
        throw SEMANTIC_ERROR (_F("invalid register field '%s' in bpf code",
                                 stmt.src1.c_str()), stmt.tok);
      if (i_src1)
        v_src1 = this_prog.new_imm(stmt.imm);
      else if (stmt.imm != 0)
        throw SEMANTIC_ERROR (_("invalid immediate field in bpf code"), stmt.tok);
    }

  if (stmt.off != (int16_t)stmt.off)
    throw SEMANTIC_ERROR (_F("offset field '%lld' out of range in bpf code", (long long) stmt.off), stmt.tok);

  if (op_jmp)
    {
      block *target = label_map[stmt.jmp_target];
      this_prog.mk_jmp(this_ins, target);
    }
  else if (op_jcond)
    {
      if (label_map.count(stmt.jmp_target) == 0)
        throw SEMANTIC_ERROR(_F("undefined jump target '%s' in bpf code",
                                stmt.jmp_target.c_str()), stmt.tok);
      if (label_map.count(stmt.fallthrough) == 0)
        throw SEMANTIC_ERROR(_F("BUG: undefined fallthrough target '%s'",
                                stmt.fallthrough.c_str()), stmt.tok);
      block *target = label_map[stmt.jmp_target];
      block *fallthrough = label_map[stmt.fallthrough];
      this_prog.mk_jcond(this_ins, c, v_dest, v_src1, target, fallthrough);
    }
  else // regular opcode
    {
      insn *i = this_ins.new_insn();
      i->code = stmt.code;
      i->dest = (r_dest ? v_dest : NULL);
      i->src0 = (r_src0 ? v_dest : NULL);
      i->src1 = v_src1;
      i->off = stmt.off;
    }
}

void
bpf_unparser::visit_embeddedcode (embeddedcode *s)
{
#ifdef DEBUG_CODEGEN
  this_ins.notes.push("asm");
#endif
  std::vector<asm_stmt> statements;
  asm_stmt stmt;

  // PR24528: The /* userspace */ annotation is used to mark
  // userspace-only BPF embeddedcode tapset functions.
  if (s->tagged_p("/* userspace */") &&
      this_prog.target == target_kernel_bpf)
    throw SEMANTIC_ERROR(_("embeddedcode marked /* userspace */ in kernel bpf probe"), s->tok);

  // track adjusted source location for each stmt
  adjusted_loc = s->tok->location;
  adjust_pos = 0;

  size_t pos = 0;
  while ((pos = parse_asm_stmt(s, pos, stmt)) != std::string::npos)
    {
      statements.push_back(stmt);
    }

  // build basic block table
  std::map<std::string, block *> label_map;
  block *entry_block = this_ins.b;
  label_map[";;entry"] = entry_block;

  bool after_label = true;
  asm_stmt *after_jump = NULL;
  unsigned fallthrough_count = 0;
  for (std::vector<asm_stmt>::iterator it = statements.begin();
       it != statements.end(); it++)
    {
      stmt = *it;

      if (after_jump != NULL && stmt.kind == "label")
        {
          after_jump->has_fallthrough = true;
          after_jump->fallthrough = stmt.dest;
        }
      else if (after_jump != NULL)
        {
          block *b = this_prog.new_block();

          // generate unique label for fallthrough edge
          std::ostringstream oss;
          oss << "fallthrough;;" << fallthrough_count++;
          std::string fallthrough_label = oss.str();
          // XXX: semicolons prevent collision with programmer-defined labels

          label_map[fallthrough_label] = b;
          set_block(b);

          after_jump->has_fallthrough = true;
          after_jump->fallthrough = fallthrough_label;
        }

      if (stmt.kind == "label" && after_label)
        {
          // avoid creating multiple blocks for consecutive labels
          label_map[stmt.dest] = this_ins.b;
          after_jump = NULL;
        }
      else if (stmt.kind == "label")
        {
          block *b = this_prog.new_block();
          label_map[stmt.dest] = b;
          set_block(b);
          after_label = true;
          after_jump = NULL;
        }
      else if (stmt.has_fallthrough)
        {
          after_label = false;
          after_jump = &*it; // be sure to refer to original, not copied stmt
        }
      else if (stmt.kind == "opcode" && BPF_CLASS(stmt.code) == BPF_JMP
               && BPF_OP(stmt.code) != BPF_CALL /* CALL stays in the same block */)
        {
          after_label = false;
          after_jump = &*it; // be sure to refer to original, not copied stmt
        }
      else
        {
          after_label = false;
          after_jump = NULL;
        }
    }
  if (after_jump != NULL) // ??? should just fall through to exit
    throw SEMANTIC_ERROR (_("BUG: bpf embeddedcode doesn't support "
                            "fallthrough on final asm_stmt"), stmt.tok);

  // emit statements
  bool jumped_already = false;
  set_block(entry_block);
  for (std::vector<asm_stmt>::iterator it = statements.begin();
       it != statements.end(); it++)
    {
      stmt = *it;
#ifdef BPF_ASM_DEBUG
      std::cerr << "bpf_asm visit_embeddedcode: " << stmt << std::endl;
#endif
      if (stmt.kind == "label")
        {
          if (!jumped_already)
            emit_jmp (label_map[stmt.dest]);
          set_block(label_map[stmt.dest]);
        }
      else if (stmt.kind == "alloc")
        {
          /* Reserve stack space and store its address in dest. */
          int ofs = -this_prog.max_tmp_space - stmt.imm;
          if (stmt.align_alloc && (-ofs) % 8 != 0) // align to double-word
            ofs -= 8 - (-ofs) % 8;
          this_prog.use_tmp_space(-ofs);
          // ??? Consider using a storage allocator and this_prog.new_obj().

          value *dest = get_asm_reg(stmt, stmt.dest);
          this_prog.mk_binary(this_ins, BPF_ADD, dest,
                              this_prog.lookup_reg(BPF_REG_10) /*frame*/,
                              this_prog.new_imm(ofs));
        }
      else if (stmt.kind == "call")
        {
          assert (!stmt.params.empty());
          std::string func_name = stmt.params[0];
          bpf_func_id hid = bpf_function_id(func_name);
          if (hid != __BPF_FUNC_MAX_ID)
            {
              // ??? For diagnostics: check if the number of arguments is correct.
              regno r = BPF_REG_1; unsigned nargs = 0;
              for (unsigned k = 1; k < stmt.params.size(); k++)
                {
                  // ??? Could make params optional to avoid the MOVs,
                  // ??? since the calling convention is well-known.
                  value *from_reg = emit_asm_arg(stmt, stmt.params[k]);
                  value *to_reg = this_prog.lookup_reg(r);
                  this_prog.mk_mov(this_ins, to_reg, from_reg);
                  nargs++; r++;
                }
              this_prog.mk_call(this_ins, hid, nargs);
              if (stmt.dest != "-")
                {
                  value *dest = get_asm_reg(stmt, stmt.dest);
                  this_prog.mk_mov(this_ins, dest,
                                   this_prog.lookup_reg(BPF_REG_0) /* returnval */);
                }
              // ??? For diagnostics: check other cases with stmt.dest.
            }
          else if (func_name == "printf" || func_name == "sprintf")
            {
              if (stmt.params.size() < 2)
                throw SEMANTIC_ERROR (_F("bpf embeddedcode '%s' expects format string, "
                                         "none provided", func_name.c_str()),
                                      stmt.tok);
              std::string format = stmt.params[1];
              if (format.size() < 2 || format[0] != '"'
                  || format[format.size()-1] != '"')
                throw SEMANTIC_ERROR (_F("bpf embeddedcode '%s' expects format string, "
                                         "but first parameter is not a string literal",
                                         func_name.c_str()), stmt.tok);
              format = format.substr(1,format.size()-2); /* strip quotes */
              format = translate_escapes(format, stmt.tok);

              size_t format_bytes = format.size() + 1;
              if (format_bytes > BPF_MAXFORMATLEN)
                throw SEMANTIC_ERROR(_("Format string for print too long"), stmt.tok);

              std::vector<value *> args;
              for (unsigned k = 2; k < stmt.params.size(); k++)
                args.push_back(emit_asm_arg(stmt, stmt.params[k]));
              if (args.size() > BPF_MAXPRINTFARGS)
                throw SEMANTIC_ERROR(_NF("additional argument to print",
                                         "too many arguments to print (%zu)",
                                         args.size(), args.size()), stmt.tok);

              bool print_to_stream = (func_name == "printf");
              value *retval = emit_print_format(format, args, print_to_stream, stmt.tok);
              if (retval != NULL && stmt.dest != "-")
                {
                  value *dest = get_asm_reg(stmt, stmt.dest);
                  this_prog.mk_mov(this_ins, dest, retval);
                }
              // ??? For diagnostics: check other cases with retval and stmt.dest.
            }
          else
            {
              // TODO: Experimental code for supporting basic functioncalls.
              // Needs improvement and simplification to work with full generality.
              // But thus far, it is sufficient for calling exit().
#if 1
              if (func_name != "exit")
                throw SEMANTIC_ERROR(_("BUG: bpf embeddedcode non-helper 'call' operation only supports printf(),sprintf(),exit() for now"), stmt.tok);
#elif 1
              throw SEMANTIC_ERROR(_("BUG: bpf embeddedcode non-helper 'call' operation only supports printf(),sprintf() for now"), stmt.tok);
#endif
#if 1
              // ???: Passing systemtap_session through all the way to here
              // seems intrusive, but less intrusive than moving
              // embedded-code assembly to the translate_globals() pass.
              symresolution_info sym (*glob.session);
              functioncall *call = new functioncall;
              call->tok = stmt.tok;
              unsigned nargs = stmt.params.size() - 1;
              std::vector<functiondecl*> fds
                = sym.find_functions (call, func_name, nargs, stmt.tok);
              delete call;

              if (fds.empty())
                // ??? Could call levenshtein_suggest() as in
                // symresolution_info::visit_functioncall().
                throw SEMANTIC_ERROR(_("bpf embeddedcode unresolved function call"), stmt.tok);
              if (fds.size() > 1)
                throw SEMANTIC_ERROR(_("bpf embeddedcode unhandled function overloading"), stmt.tok);
              functiondecl *f = fds[0];
              // TODO: Imitation of semantic_pass_symbols, does not
              // cover full generality of the lookup process.
              update_visitor_loop (*glob.session, glob.session->code_filters, f->body);
              sym.current_function = f; sym.current_probe = 0;
              f->body->visit (&sym);

              // ??? For now, always inline the function call.
              for (auto i = func_calls.begin(); i != func_calls.end(); ++i)
                if (f == *i)
                  throw SEMANTIC_ERROR (_("unhandled function recursion"), stmt.tok);

              // Collect the function arguments.
              std::vector<value *> args;
              for (unsigned k = 1; k < stmt.params.size(); k++)
                args.push_back(emit_asm_arg(stmt, stmt.params[k]));

              if (args.size () != f->formal_args.size())
                throw SEMANTIC_ERROR(_F("bpf embeddedcode call to function '%s' "
                                        "expected %zu arguments, got %zu",
                                        func_name.c_str(),
                                        f->formal_args.size(), args.size()),
                                     stmt.tok);

              value *retval = emit_functioncall(f, args);
              if (stmt.dest != "-")
                {
                  value *dest = get_asm_reg(stmt, stmt.dest);
                  this_prog.mk_mov(this_ins, dest, retval);
                }
              // ??? For diagnostics: check other cases with retval and stmt.dest.
#endif
            }
        }
      else if (stmt.kind == "opcode")
        {
          emit_asm_opcode (stmt, label_map);
        }
      else
        throw SEMANTIC_ERROR (_F("BUG: bpf embeddedcode contains unexpected "
                                 "asm_stmt kind '%s'", stmt.kind.c_str()),
                              stmt.tok);
      if (stmt.has_fallthrough)
        {
          jumped_already = true;
          set_block(label_map[stmt.fallthrough]);
        }
      else
        jumped_already = false;
    }

  // housekeeping -- deallocate adjusted_toks along with statements
  for (std::vector<token *>::iterator it = adjusted_toks.begin();
       it != adjusted_toks.end(); it++)
    delete *it;
  adjusted_toks.clear();

#ifdef DEBUG_CODEGEN
  this_ins.notes.pop(); // asm
#endif
}

void
bpf_unparser::visit_null_statement (null_statement *)
{ }

void
bpf_unparser::visit_expr_statement (expr_statement *s)
{
  (void) emit_expr (s->value);
}

void
bpf_unparser::visit_if_statement (if_statement* s)
{
  block *then_block = this_prog.new_block ();
  block *join_block = this_prog.new_block ();

  if (s->elseblock)
    {
      block *else_block = this_prog.new_block ();
      emit_cond (s->condition, then_block, else_block);

      set_block (then_block);
      emit_stmt (s->thenblock);
      if (in_block ())
	emit_jmp (join_block);

      set_block (else_block);
      emit_stmt (s->elseblock);
      if (in_block ())
	emit_jmp (join_block);
    }
  else
    {
      emit_cond (s->condition, then_block, join_block);

      set_block (then_block);
      emit_stmt (s->thenblock);
      if (in_block ())
	emit_jmp (join_block);
    }
  set_block (join_block);
}

void
bpf_unparser::visit_for_loop (for_loop* s)
{
  // PR24528: Userspace-only feature.
  if (this_prog.target == target_kernel_bpf)
    throw SEMANTIC_ERROR(_("unsupported loop in bpf kernel probe"), s->tok);
  // TODO: Future versions of BPF will include limited looping capability.

  block *body_block = this_prog.new_block ();
  block *iter_block = this_prog.new_block ();
  block *test_block = this_prog.new_block ();
  block *join_block = this_prog.new_block ();

  emit_stmt (s->init);
  if (!in_block ())
    return;
  emit_jmp (test_block);

  loop_break.push_back (join_block);
  loop_cont.push_back (iter_block);

  set_block (body_block);
  emit_stmt (s->block);
  if (in_block ())
    emit_jmp (iter_block);

  loop_cont.pop_back ();
  loop_break.pop_back ();

  set_block (iter_block);
  emit_stmt (s->incr);
  if (in_block ())
    emit_jmp (test_block);

  set_block (test_block);
  emit_cond (s->cond, body_block, join_block);

  set_block (join_block);
}

void
bpf_unparser::visit_foreach_loop(foreach_loop* s)
{
  // PR24528: Userspace-only feature.
  if (this_prog.target == target_kernel_bpf)
    throw SEMANTIC_ERROR(_("unsupported loop in bpf kernel probe"), s->tok);
  // TODO: Future versions of BPF will include limited looping capability.

  if (s->indexes.size() != 1)
   throw SEMANTIC_ERROR(_("unhandled multi-dimensional array"), s->tok);

  vardecl *keydecl = s->indexes[0]->referent;
  auto i = this_locals->find(keydecl);
  if (i == this_locals->end())
    throw SEMANTIC_ERROR(_("unknown index"), keydecl->tok);

  symbol *a;
  if (! (a = dynamic_cast<symbol *>(s->base)))
    throw SEMANTIC_ERROR(_("unknown type"), s->base->tok);
  vardecl *arraydecl = a->referent;

  // PR23875: foreach should handle string keys
  auto type = arraydecl->index_types[0];
  if (type != pe_long && type != pe_string)
    throw SEMANTIC_ERROR(_("unhandled foreach index type"), s->tok);
  int keysize = 8; // XXX: If a string key, foreach will handle a pointer to it.

  auto g = glob.globals.find(arraydecl);
  if (g == glob.globals.end())
    throw SEMANTIC_ERROR(_("unknown array"), arraydecl->tok);

  int map_id = g->second.map_id;
  // PR23476: Handle foreach iteration for stats arrays.
  assert (!g->second.is_scalar());
  if (g->second.is_stat())
    {
      auto all_fields = glob.array_stats.find(arraydecl);
      if (all_fields == glob.array_stats.end())
        throw SEMANTIC_ERROR(_("unknown stats array"), arraydecl->tok);
      auto one_field = all_fields->second.find(globals::stat_iter_field);
      assert (one_field != all_fields->second.end());
      map_id = one_field->second;
      // XXX: Since foreach only handles/returns keys, it's sufficient
      // to simply iterate one of the stat field maps.

      // If sorting on aggregate is required (s->sort_aggr),
      // map_get_next_key will need to perform aggregation
      // calculations that might require access to more than one map.
      //
      // TODO PR24528: need to pass sort_aggr to the interpreter.
      // TODO PR24528: use existing foreach_sort_stat.exp testcase to check this.
      if (s->sort_column == 0)
        throw SEMANTIC_ERROR(_("unsupported sorted iteration on stat aggregate"), arraydecl->tok);
    }

  value *limit = this_prog.new_reg();
  value *key = i->second;
  value *i0 = this_prog.new_imm(0);
  value *key_ofs = this_prog.new_imm(-keysize);
  value *newkey_ofs = this_prog.new_imm(-keysize-keysize);
  value *frame = this_prog.lookup_reg(BPF_REG_10);
  block *body_block = this_prog.new_block ();
  block *load_block_1 = this_prog.new_block ();
  block *iter_block = this_prog.new_block ();
  block *join_block = this_prog.new_block ();

  // Track iteration limit.
  if (s->limit)
    this_prog.mk_mov(this_ins, limit, emit_expr(s->limit));
  else
    // XXX may want 'limit = this_prog.new_imm(-1);'
    this_prog.mk_mov(this_ins, limit, this_prog.new_imm(-1));

  // XXX: s->sort_column may be uninitialized if s->sort_direction == 0
  unsigned sort_column = s->sort_column;
  //unsigned sort_column = s->sort_direction == 0 ? 0 : s->sort_column;

  // Get the first key.
  this_prog.load_map (this_ins, this_prog.lookup_reg(BPF_REG_1), map_id);
  this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_2), i0);
  this_prog.mk_binary (this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_3), 
                       frame, newkey_ofs);
  this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_4),
                    this_prog.new_imm(SORT_FLAGS(sort_column,s->sort_direction)));
  this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_5), limit);
  this_prog.mk_call (this_ins, BPF_FUNC_map_get_next_key, 5);
  this_prog.mk_jcond (this_ins, NE, this_prog.lookup_reg(BPF_REG_0), i0,
                      join_block, load_block_1);

  this_prog.use_tmp_space(2*keysize);

  emit_jmp(load_block_1);

  // Do loop body
  loop_break.push_back (join_block);
  loop_cont.push_back (iter_block);

  set_block(body_block);
  emit_stmt(s->block);
  if (in_block ())
    emit_jmp(iter_block);

  loop_cont.pop_back ();
  loop_break.pop_back ();

  // Call map_get_next_key, exit loop if it doesn't return 0
  set_block(iter_block);

  this_prog.load_map (this_ins, this_prog.lookup_reg(BPF_REG_1), map_id);
  this_prog.mk_st (this_ins, BPF_DW, frame, -keysize, key);
  this_prog.mk_binary (this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_2),
                       frame, key_ofs);
  this_prog.mk_binary (this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_3),
                       frame, newkey_ofs);
  this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_4),
                    this_prog.new_imm(SORT_FLAGS(sort_column,s->sort_direction)));
  this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_5), limit);
  this_prog.mk_call (this_ins, BPF_FUNC_map_get_next_key, 5);
  this_prog.mk_jcond (this_ins, NE, this_prog.lookup_reg(BPF_REG_0), i0,
                      join_block, load_block_1);

  // Load next key, decrement limit if applicable
  set_block(load_block_1);

  // Return the key. If it's a string, it's already a string address.
  this_prog.mk_ld (this_ins, BPF_DW, key, frame, -keysize-keysize);

  // If the foreach loop iterates over the value, then fetch it too.
  if (s->value)
    {
      vardecl *valdecl = s->value->referent;

      auto j = this_locals->find(valdecl);
      if (j == this_locals->end())
        throw SEMANTIC_ERROR(_("unknown value"), valdecl->tok);

      value *val = j->second;
      block *load_block_2 = this_prog.new_block ();

      // To lookup value, we need to pass a pointer to the key. If the key is an
      // integer, we need to pass the location in the stack.
      this_prog.load_map (this_ins, this_prog.lookup_reg(BPF_REG_1), map_id);
      switch (keydecl->type)
        {
          case pe_long:
            this_prog.mk_binary (this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_2),
                                 frame, newkey_ofs);
            break;
          case pe_string:
            this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_2), key);
            break;
          default:
            throw SEMANTIC_ERROR (_("unhandled foreach key type"), keydecl->tok);
        }

      this_prog.mk_call (this_ins, BPF_FUNC_map_lookup_elem, 2);
      this_prog.mk_jcond (this_ins, EQ, this_prog.lookup_reg(BPF_REG_0), i0,
                          join_block, load_block_2);

      // Load the corresponding value if key is valid.
      set_block(load_block_2);

      // If the value is an integer, we must deference the pointer.
      switch (valdecl->type)
        {
          case pe_long:
            this_prog.mk_ld(this_ins, BPF_DW, val, this_prog.lookup_reg(BPF_REG_0), 0);
            break;
          case pe_string:
            this_prog.mk_mov(this_ins, val, this_prog.lookup_reg(BPF_REG_0));
            break;
          default:
            throw SEMANTIC_ERROR (_("unhandled foreach value type"), valdecl->tok);
        }
    }

  if (s->limit)
      this_prog.mk_binary (this_ins, BPF_ADD, limit, limit, this_prog.new_imm(-1));

  emit_jmp(body_block);
  set_block(join_block);
}

void
bpf_unparser::visit_break_statement (break_statement* s)
{
  if (loop_break.empty ())
    throw SEMANTIC_ERROR (_("cannot 'break' outside loop"), s->tok);
  emit_jmp (loop_break.back ());
}

void
bpf_unparser:: visit_continue_statement (continue_statement* s)
{
  if (loop_cont.empty ())
    throw SEMANTIC_ERROR (_("cannot 'continue' outside loop"), s->tok);
  emit_jmp (loop_cont.back ());
}

void
bpf_unparser::visit_return_statement (return_statement* s)
{
  if (func_return.empty ())
    throw SEMANTIC_ERROR (_("cannot 'return' outside function"), s->tok);
  assert (!func_return_val.empty ());
  if (s->value)
    emit_mov (func_return_val.back (), emit_expr (s->value));
  emit_jmp (func_return.back ());
}

void
bpf_unparser::visit_next_statement (next_statement* s)
{
  if (!func_return.empty ())
    throw SEMANTIC_ERROR(_("bpf unhandled next statement in function"), s->tok);
  emit_jmp(exit_block);
}

void
bpf_unparser::visit_delete_statement (delete_statement *s)
{
  expression *e = s->value;
  if (symbol *s = dynamic_cast<symbol *>(e))
    {
      vardecl *var = s->referent;
      if (var->arity != 0)
	throw SEMANTIC_ERROR (_("unimplemented delete of array"), s->tok);

      auto g = glob.globals.find (var);
      if (g != glob.globals.end())
	{
	  value *frame = this_prog.lookup_reg(BPF_REG_10);
	  int key_ofs, val_ofs;

	  switch (var->type)
	    {
	    case pe_long:
	      val_ofs = -8;
	      this_prog.mk_st(this_ins, BPF_DW, frame, val_ofs,
			      this_prog.new_imm(0));
	      this_prog.mk_binary(this_ins, BPF_ADD,
				  this_prog.lookup_reg(BPF_REG_3),
				  frame, this_prog.new_imm(val_ofs));
	      break;
	    // ??? pe_string -> (2) TODO delete ref (but leave the storage for later cleanup of the entire containing struct?)
            // ??? pe_stats -> TODOXXX
	    default:
	      goto err;
	    }

	  key_ofs = val_ofs - 4;
	  this_prog.mk_st(this_ins, BPF_W, frame, key_ofs,
			  this_prog.new_imm(g->second.idx));
	  this_prog.use_tmp_space(-key_ofs);

          // TODO: Handle map_id < 0 for pe_stats, or assert otherwise.
          if (g->second.map_id < 0)
            throw SEMANTIC_ERROR (_("unsupported delete operation on statistics aggregate"), s->tok); // TODOXXX PR23476
	  this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1),
			     g->second.map_id);
	  this_prog.mk_binary(this_ins, BPF_ADD,
			      this_prog.lookup_reg(BPF_REG_2),
			      frame, this_prog.new_imm(key_ofs));
	  emit_mov(this_prog.lookup_reg(BPF_REG_4), this_prog.new_imm(0));
	  this_prog.mk_call(this_ins, BPF_FUNC_map_update_elem, 4);
	  return;
	}

      auto i = this_locals->find (var);
      if (i != this_locals->end ())
	{
	  emit_mov (i->second, this_prog.new_imm(0));
	  return;
	}
    }
  else if (arrayindex *a = dynamic_cast<arrayindex *>(e))
    {
      if (symbol *a_sym = dynamic_cast<symbol *>(a->base))
	{
	  vardecl *v = a_sym->referent;
	  int key_ofs = 0;

	  auto g = glob.globals.find(v);
	  if (g == glob.globals.end())
	    throw SEMANTIC_ERROR(_("unknown array variable"), v->tok);

	  unsigned element = v->arity;

	  // iterate over the elements
	  do {
	    --element;
	    value *idx = emit_expr(a->indexes[element]);
	    switch (v->index_types[element])
	      {
	      case pe_long:
	        // Store the long on the stack and pass its address:
	        key_ofs -= 8;
	        emit_long_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
	        break;
              case pe_string:
                // Zero-pad and copy the string to the stack and pass its address:
                key_ofs -= BPF_MAXSTRINGLEN;
                emit_str_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
                break;
	      default:
	        throw SEMANTIC_ERROR(_("unhandled index type"), e->tok);
	      }
	  } while (element);
          this_prog.use_tmp_space(-key_ofs);

          // TODO: Handle map_id < 0 for pe_stats or assert otherwise.
          if (g->second.map_id < 0)
            throw SEMANTIC_ERROR (_("unsupported delete operation on statistics aggregate"), a->tok); // TODOXXX PR23476
	  this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1),
			     g->second.map_id);
	  this_prog.mk_call(this_ins, BPF_FUNC_map_delete_elem, 2);
	  return;
	}
    }
 err:
  throw SEMANTIC_ERROR (_("unknown lvalue"), e->tok);
}

// Translate string escape characters.
// Accepts strings produced by parse.cxx lexer::scan and
// by the eBPF embedded-code assembler.
//
// PR23559: This is currently an eBPF-only version of the function
// that does not translate octal escapes.
std::string
translate_escapes (const interned_string &str, const token* tok)
{
  std::string result;
  bool saw_esc = false;
  for (interned_string::const_iterator j = str.begin();
       j != str.end(); ++j)
    {
      if (saw_esc)
        {
          saw_esc = false;
          switch (*j)
            {
            case 'f': result += '\f'; break;
            case 'n': result += '\n'; break;
            case 'r': result += '\r'; break;
            case 't': result += '\t'; break;
            case 'v': result += '\v'; break;

            // Translate octal and hex escapes:
            case '0' ... '7':
              {
                unsigned int c = 0;
                // An octal escape sequence is at most 3 characters.
                for (unsigned k = 0; k < 3; ++k)
                  {
                    c = c * 8 + (*j - '0');
                    ++j;
                    if (j == str.end() || *j < '0' || *j > '7')
                      {
                        --j; // avoid swallowing extra char
                        break;
                      }
                  }
                
                // TODO: this check should be performed by the parser
                if (c > 255 /* \377 */)
                  throw SEMANTIC_ERROR (_("octal escape sequence out of range"), tok);

                if (c != 0) // XXX skip '\0' as it can break a transport tag
                  result += (char) c;
              }
              break;
            case 'x':
              {
                unsigned int c = 0; ++j;
                // A hex escape sequence is arbitrarily long.
                // XXX: Behaviour is 'undefined' when overflowing char.
                for (; j != str.end(); ++j)
                  {
                    if (*j >= '0' && *j <= '9')
                      c = c * 16 + (*j - '0');
                    else if (*j >= 'a' && *j <= 'f')
                      c = c * 16 + (*j - 'a' + 10);
                    else if (*j >= 'A' && *j <= 'F')
                      c = c * 16 + (*j - 'A' + 10);
                    else
                      {
                        --j; // avoid swallowing extra char
                        break;
                      }
                  }

                // TODO: this check should be performed by the parser
                if (c > 0xff)
                  throw SEMANTIC_ERROR (_("hex escape sequence out of range"), tok);

                if (c != 0) // XXX skip '\0' as it can break a transport tag
                  result += (char) c;

                // If we've hit the end of the string , then return the result.
                if (j == str.end())
                  return result;
              }
              break;

            default:  result += *j; break;
            }
        }
      else if (*j == '\\')
        saw_esc = true;
      else
        result += *j;
    }
  return result;
}

value *
bpf_unparser::emit_literal_string (const std::string &str, const token *tok)
{
  size_t str_bytes = str.size() + 1;
  if (str_bytes > BPF_MAXSTRINGLEN)
    throw SEMANTIC_ERROR(_("string literal too long"), tok);
  return this_prog.new_str(str); // will be lowered to a pointer by bpf-opt.cxx
}

void
bpf_unparser::visit_literal_string (literal_string* e)
{
  interned_string v = e->value;
  std::string str = translate_escapes(v, e->tok);
  result = emit_literal_string(str, e->tok);
}

void
bpf_unparser::visit_literal_number (literal_number* e)
{
  result = this_prog.new_imm(e->value);
}

void
bpf_unparser::visit_binary_expression (binary_expression* e)
{
  int code;
  if (e->op == "+")
    code = BPF_ADD;
  else if (e->op == "-")
    code = BPF_SUB;
  else if (e->op == "*")
    code = BPF_MUL;
  else if (e->op == "&")
    code = BPF_AND;
  else if (e->op == "|")
    code = BPF_OR;
  else if (e->op == "^")
    code = BPF_XOR;
  else if (e->op == "<<")
    code = BPF_LSH;
  else if (e->op == ">>")
    code = BPF_ARSH;
  else if (e->op == ">>>")
    code = BPF_RSH;
  else if (e->op == "/")
    code = BPF_DIV;
  else if (e->op == "%")
    code = BPF_MOD;
  else
    throw SEMANTIC_ERROR (_("unhandled binary operator"), e->tok);

  value *s0 = this_prog.new_reg();
  // copy e->left into a seperate reg in case evaluating e->right
  // causes e->left to mutate (ex. x + x++).
  this_prog.mk_mov(this_ins, s0, emit_expr (e->left));

  value *s1 = emit_expr (e->right);
  value *d = this_prog.new_reg ();
  this_prog.mk_binary (this_ins, code, d, s0, s1);
  result = d;
}

void
bpf_unparser::visit_unary_expression (unary_expression* e)
{
  if (e->op == "-")
    {
      // Note that negative literals appear in the script langauge as
      // unary negations over positive literals.
      if (literal_number *lit = dynamic_cast<literal_number *>(e))
	result = this_prog.new_imm(-(uint64_t)lit->value);
      else
	{
	  value *s = emit_expr (e->operand);
	  value *d = this_prog.new_reg();
	  this_prog.mk_unary (this_ins, BPF_NEG, d, s);
	  result = d;
	}
    }
  else if (e->op == "~")
    {
      value *s1 = this_prog.new_imm(-1);
      value *s0 = emit_expr (e->operand);
      value *d = this_prog.new_reg ();
      this_prog.mk_binary (this_ins, BPF_XOR, d, s0, s1);
      result = d;
    }
  else if (e->op == "!")
    result = emit_bool (e);
  else if (e->op == "+")
    result = emit_expr (e->operand);
  else
    throw SEMANTIC_ERROR (_("unhandled unary operator"), e->tok);
}

void
bpf_unparser::visit_pre_crement (pre_crement* e)
{
  int dir;
  if (e->op == "++")
    dir = 1;
  else if (e->op == "--")
    dir = -1;
  else
    throw SEMANTIC_ERROR (_("unhandled crement operator"), e->tok);

  value *c = this_prog.new_imm(dir);
  value *v = emit_expr (e->operand);
  this_prog.mk_binary (this_ins, BPF_ADD, v, v, c);
  emit_store (e->operand, v);
  result = v;
}

void
bpf_unparser::visit_post_crement (post_crement* e)
{
  int dir;
  if (e->op == "++")
    dir = 1;
  else if (e->op == "--")
    dir = -1;
  else
    throw SEMANTIC_ERROR (_("unhandled crement operator"), e->tok);

  value *c = this_prog.new_imm(dir);
  value *r = this_prog.new_reg ();
  value *v = emit_expr (e->operand);

  emit_mov (r, v);
  this_prog.mk_binary (this_ins, BPF_ADD, v, v, c);
  emit_store (e->operand, v);
  result = r;
}

void
bpf_unparser::visit_logical_or_expr (logical_or_expr* e)
{
  result = emit_bool (e);
}

void
bpf_unparser::visit_logical_and_expr (logical_and_expr* e)
{
  result = emit_bool (e);
}

// ??? This matches the code in translate.cxx, but it looks like the
// functionality has been disabled in the SystemTap parser.
void
bpf_unparser::visit_compound_expression (compound_expression* e)
{
  e->left->visit(this);
  e->right->visit(this); // overwrite result of first expression
}

void
bpf_unparser::visit_comparison (comparison* e)
{
  result = emit_bool (e);
}

void
bpf_unparser::visit_concatenation (concatenation* e) 
{
  if (this_prog.target == target_kernel_bpf)
    throw SEMANTIC_ERROR(_("unsupported in bpf kernel probe"), e->tok);

  // We make use of many temporary registers because intermediate strings 
  // can arise from function calls which may clobber registers that hold data.
 
  value *l = emit_expr (e->left);
  value* placeholder_l = this_prog.new_reg();
  this_prog.mk_mov(this_ins, placeholder_l, l); 

  value *r = emit_expr (e->right);
  value* placeholder_r = this_prog.new_reg();
  this_prog.mk_mov(this_ins, placeholder_r, r);

  this_prog.mk_mov(this_ins, this_prog.lookup_reg(BPF_REG_1), placeholder_l);
  this_prog.mk_mov(this_ins, this_prog.lookup_reg(BPF_REG_2), placeholder_r);

  // Call function to concatenate. 
  this_prog.mk_call(this_ins, BPF_FUNC_str_concat, 2);

  value* str = this_prog.new_reg();
  this_prog.mk_mov(this_ins, str, this_prog.lookup_reg(BPF_REG_0)); 

  result = str;
}

void
bpf_unparser::visit_ternary_expression (ternary_expression* e)
{
  block *join_block = this_prog.new_block ();
  value *r = this_prog.new_reg ();

  if (!has_side_effects (e->truevalue))
    {
      block *else_block = this_prog.new_block ();

      emit_mov (r, emit_expr (e->truevalue));
      emit_cond (e->cond, join_block, else_block);

      set_block (else_block);
      emit_mov (r, emit_expr (e->falsevalue));
      emit_jmp (join_block);
    }
  else if (!has_side_effects (e->falsevalue))
    {
      block *then_block = this_prog.new_block ();

      emit_mov (r, emit_expr (e->falsevalue));
      emit_cond (e->cond, join_block, then_block);

      set_block (then_block);
      emit_mov (r, emit_expr (e->truevalue));
      emit_jmp (join_block);
    }
  else
    {
      block *then_block = this_prog.new_block ();
      block *else_block = this_prog.new_block ();
      emit_cond (e->cond, then_block, else_block);

      set_block (then_block);
      emit_mov (r, emit_expr (e->truevalue));
      emit_jmp (join_block);

      set_block (else_block);
      emit_mov (r, emit_expr (e->falsevalue));
      emit_jmp (join_block);
    }

  set_block (join_block);
  result = r;
}

void
bpf_unparser::visit_assignment (assignment* e)
{
  value *r = emit_expr (e->right);

  if (e->op == "<<<")
    ; // XXX: handled by emit_store(), which checks for statistics lvalue
  else if (e->op != "=")
    {
      int code;
      if (e->op == "+=")
	code = BPF_ADD;
      else if (e->op == "-=")
	code = BPF_SUB;
      else if (e->op == "*=")
	code = BPF_MUL;
      else if (e->op == "/=")
	code = BPF_DIV;
      else if (e->op == "%=")
	code = BPF_MOD;
      else if (e->op == "<<=")
	code = BPF_LSH;
      else if (e->op == ">>=")
	code = BPF_ARSH;
      else if (e->op == "&=")
	code = BPF_AND;
      else if (e->op == "^=")
	code = BPF_XOR;
      else if (e->op == "|=")
	code = BPF_OR;
      else
	throw SEMANTIC_ERROR (_("unhandled assignment operator"), e->tok);

      value *l = emit_expr (e->left);
      this_prog.mk_binary (this_ins, code, l, l, r);
      r = l;
    }

  emit_store (e->left, r);
  result = r;
}

value *
bpf_unparser::emit_context_var(bpf_context_vardecl *v)
{
  // similar to visit_target_deref but the size/offset info
  // is given in v->size/v->offset instead of an expression.
  value *d = this_prog.new_reg();

  if (v->size > 8)
    {
      // Compute a pointer but do not dereference. Needed
      // for array context variables.
      this_prog.mk_binary (this_ins, BPF_ADD, d, this_in_arg0,
                           this_prog.new_imm(v->offset));

      return d;
    }

  value *frame = this_prog.lookup_reg(BPF_REG_10);

  this_prog.mk_binary (this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_3),
                       this_in_arg0, this_prog.new_imm(v->offset));
  this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_2),
                    this_prog.new_imm(v->size));
  this_prog.mk_binary (this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_1),
                       frame, this_prog.new_imm(-v->size));
  this_prog.use_tmp_space (v->size);

  this_prog.mk_call (this_ins, BPF_FUNC_probe_read, 3);

  int opc;
  switch (v->size)
    {
    case 1: opc = BPF_B; break;
    case 2: opc = BPF_H; break;
    case 4: opc = BPF_W; break;
    case 8: opc = BPF_DW; break;

    default: assert(0);
    }

  this_prog.mk_ld (this_ins, opc, d, frame, -v->size);

  if (v->is_signed && v->size < 8)
    {
      value *sh = this_prog.new_imm ((8 - v->size) * 8);
      this_prog.mk_binary (this_ins, BPF_LSH, d, d, sh);
      this_prog.mk_binary (this_ins, BPF_ARSH, d, d, sh);
    }

  return d;
}

void
bpf_unparser::visit_symbol(symbol *s)
{
  vardecl *v = s->referent;
  assert (v->arity < 1);

  if (bpf_context_vardecl *c = dynamic_cast<bpf_context_vardecl*>(v))
    {
      result = emit_context_var(c);
      return;
    }

  auto g = glob.globals.find (v);
  if (g != glob.globals.end())
    {
      if (g->second.is_stat())
        throw SEMANTIC_ERROR (_("unhandled statistics variable"), s->tok); // TODOXXX PR23476

      value *frame = this_prog.lookup_reg(BPF_REG_10);
      this_prog.mk_st(this_ins, BPF_W, frame, -4,
		      this_prog.new_imm(g->second.idx));
      this_prog.use_tmp_space(4);

      this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1),
			 g->second.map_id);
      this_prog.mk_binary(this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_2),
			  frame, this_prog.new_imm(-4));
      this_prog.mk_call(this_ins, BPF_FUNC_map_lookup_elem, 2);

      value *r0 = this_prog.lookup_reg(BPF_REG_0);
      value *i0 = this_prog.new_imm(0);
      block *cont_block = this_prog.new_block();
      block *exit_block = get_exit_block();

      // Note that the kernel bpf verifier requires that we check that
      // the pointer is non-null.
      this_prog.mk_jcond(this_ins, EQ, r0, i0, exit_block, cont_block);

      set_block(cont_block);

      result = this_prog.new_reg();
      switch (v->type)
	{
	case pe_long:
	  this_prog.mk_ld(this_ins, BPF_DW, result, r0, 0);
	  break;
        case pe_string:
          // Just return the address of the string within the map:
          emit_mov(result, r0);
          break;
	default:
	  throw SEMANTIC_ERROR (_("unhandled global variable type"), s->tok);
	}
      return;
    }

  // ??? Maybe use result = this_locals.at (v);
  // to throw std::out_of_range on lookup failure.
  auto l = this_locals->find (v);
  if (l != this_locals->end())
    {
      result = (*l).second;
      return;
    }
  throw SEMANTIC_ERROR (_("unknown variable"), s->tok);
}

void
bpf_unparser::visit_arrayindex(arrayindex *e)
{
  if (symbol *sym = dynamic_cast<symbol *>(e->base))
    {
      vardecl *v = sym->referent;

      auto g = glob.globals.find(v);
      if (g == glob.globals.end())
	throw SEMANTIC_ERROR(_("unknown array variable"), v->tok);

      if (g->second.is_stat())
        throw SEMANTIC_ERROR (_("unhandled statistics variable"), v->tok); // TODOXXX PR23476

      unsigned element = v->arity;
      int key_ofs = 0;

      // iterate over the elements
      do {
	--element;
	value *idx = emit_expr(e->indexes[element]);
	switch (v->index_types[element])
	  {
	  case pe_long:
	    // Store the long on the stack and pass its address:
	    key_ofs -= 8;
	    emit_long_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
	    break;
          case pe_string:
            // Zero-pad and copy the string to the stack and pass its address:
	    key_ofs -= BPF_MAXSTRINGLEN;
            emit_str_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
            break;
	  default:
	    throw SEMANTIC_ERROR(_("unhandled index type"), e->tok);
	}
      } while (element);
      this_prog.use_tmp_space(-key_ofs);

      this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1),
			 g->second.map_id);

      value *r0 = this_prog.lookup_reg(BPF_REG_0);
      value *i0 = this_prog.new_imm(0);
      block *t_block = this_prog.new_block();
      block *f_block = this_prog.new_block();
      block *join_block = this_prog.new_block();
      result = this_prog.new_reg();

      this_prog.mk_call(this_ins, BPF_FUNC_map_lookup_elem, 2);
      this_prog.mk_jcond(this_ins, EQ, r0, i0, t_block, f_block);

      // Key is not in the array. Evaluate to 0.
      set_block(t_block);
      emit_mov(result, i0);
      emit_jmp(join_block);

      // Key is in the array. Get value from stack.
      set_block(f_block);
      if (v->type == pe_long)
	this_prog.mk_ld(this_ins, BPF_DW, result, r0, 0);
      else
	emit_mov(result, r0);

      emit_jmp(join_block);
      set_block(join_block);
    }
  else
    throw SEMANTIC_ERROR(_("unhandled arrayindex expression"), e->tok);
}

void
bpf_unparser::visit_array_in(array_in* e)
{
  arrayindex *a = e->operand;

  if (symbol *s = dynamic_cast<symbol *>(a->base))
    {
      vardecl *v = s->referent;

      auto g = glob.globals.find (v);

      if (g == glob.globals.end())
        throw SEMANTIC_ERROR(_("unknown variable"), v->tok);

      unsigned element = v->arity;
      int key_ofs = 0;

      // iterate over the elements
      do {
	--element;
	value *idx = emit_expr(a->indexes[element]);

	switch(v->index_types[element])
          {
	  case pe_long:
            // Store the long on the stack and pass its address:
	    key_ofs -= 8;
            emit_long_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
            break;
          case pe_string:
            // Zero-pad and copy the string to the stack and pass its address:
	    key_ofs -= BPF_MAXSTRINGLEN;
            emit_str_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
            break;
          default:
            throw SEMANTIC_ERROR(_("unhandled index type"), e->tok);
          }
      } while (element);
      this_prog.use_tmp_space(-key_ofs);

      // TODO: Handle map_id < 0 for pe_stats or assert otherwise.
      if (g->second.map_id < 0)
        throw SEMANTIC_ERROR (_("unsupported array-in operation on statistics aggregate"), s->tok); // TODOXXX PR23476
      this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1),
                         g->second.map_id);
      this_prog.mk_call(this_ins, BPF_FUNC_map_lookup_elem, 2);

      value *r0 = this_prog.lookup_reg(BPF_REG_0);
      value *i0 = this_prog.new_imm(0);
      value *i1 = this_prog.new_imm(1);
      value *d = this_prog.new_reg();

      block *b0 = this_prog.new_block();
      block *b1 = this_prog.new_block();
      block *cont_block = this_prog.new_block();

      this_prog.mk_jcond(this_ins, EQ, r0, i0, b0, b1);

      // d = 0
      set_block(b0);
      this_prog.mk_mov(this_ins, d, i0);
      b0->fallthru = new edge(b0, cont_block);

      // d = 1
      set_block(b1);
      this_prog.mk_mov(this_ins, d, i1);
      b1->fallthru = new edge(b1, cont_block);

      set_block(cont_block);
      result = d;

      return;
    }
  /// ??? hist_op

  throw SEMANTIC_ERROR(_("unhandled operand type"), a->base->tok);
}

void
bpf_unparser::visit_target_deref (target_deref* e)
{
  // ??? For some hosts, including x86_64, it works to read userspace
  // and kernelspace with the same function.  For others, like s390x,
  // this only works to read kernelspace.

  value *src = emit_expr (e->addr);
  value *frame = this_prog.lookup_reg (BPF_REG_10);

  this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_3), src);
  this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_2),
		    this_prog.new_imm (e->size));
  this_prog.mk_binary (this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_1),
		       frame, this_prog.new_imm (-(int64_t)e->size));
  this_prog.use_tmp_space(e->size);

  this_prog.mk_call(this_ins, BPF_FUNC_probe_read, 3);

  value *d = this_prog.new_reg ();
  int opc;
  switch (e->size)
    {
    case 1: opc = BPF_B; break;
    case 2: opc = BPF_H; break;
    case 4: opc = BPF_W; break;
    case 8: opc = BPF_DW; break;
    default:
      throw SEMANTIC_ERROR(_("unhandled deref size"), e->tok);
    }
  this_prog.mk_ld (this_ins, opc, d, frame, -e->size);

  if (e->signed_p && e->size < 8)
    {
      value *sh = this_prog.new_imm ((8 - e->size) * 8);
      this_prog.mk_binary (this_ins, BPF_LSH, d, d, sh);
      this_prog.mk_binary (this_ins, BPF_ARSH, d, d, sh);
    }
  result = d;
}

void
bpf_unparser::visit_target_register (target_register* e)
{
  // ??? Should not hard-code register size.
  int size = sizeof(void *);
  // ??? Should not hard-code register offsets in pr_regs.
  int ofs = 0;
  switch (e->regno)
    {
#if defined(__i386__)
    case  0: ofs = offsetof(pt_regs, eax); break;
    case  1: ofs = offsetof(pt_regs, ecx); break;
    case  2: ofs = offsetof(pt_regs, edx); break;
    case  3: ofs = offsetof(pt_regs, ebx); break;
    case  4: ofs = offsetof(pt_regs, esp); break;
    case  5: ofs = offsetof(pt_regs, ebp); break;
    case  6: ofs = offsetof(pt_regs, esi); break;
    case  7: ofs = offsetof(pt_regs, edi); break;
    case  8: ofs = offsetof(pt_regs, eip); break;
#elif defined(__x86_64__)
    case  0: ofs = offsetof(pt_regs, rax); break;
    case  1: ofs = offsetof(pt_regs, rdx); break;
    case  2: ofs = offsetof(pt_regs, rcx); break;
    case  3: ofs = offsetof(pt_regs, rbx); break;
    case  4: ofs = offsetof(pt_regs, rsi); break;
    case  5: ofs = offsetof(pt_regs, rdi); break;
    case  6: ofs = offsetof(pt_regs, rbp); break;
    case  7: ofs = offsetof(pt_regs, rsp); break;
    case  8: ofs = offsetof(pt_regs, r8); break;
    case  9: ofs = offsetof(pt_regs, r9); break;
    case 10: ofs = offsetof(pt_regs, r10); break;
    case 11: ofs = offsetof(pt_regs, r11); break;
    case 12: ofs = offsetof(pt_regs, r12); break;
    case 13: ofs = offsetof(pt_regs, r13); break;
    case 14: ofs = offsetof(pt_regs, r14); break;
    case 15: ofs = offsetof(pt_regs, r15); break;
    case 16: ofs = offsetof(pt_regs, rip); break;
#elif defined(__arm__)
    case  0: ofs = offsetof(pt_regs, uregs[0]); break;
    case  1: ofs = offsetof(pt_regs, uregs[1]); break;
    case  2: ofs = offsetof(pt_regs, uregs[2]); break;
    case  3: ofs = offsetof(pt_regs, uregs[3]); break;
    case  4: ofs = offsetof(pt_regs, uregs[4]); break;
    case  5: ofs = offsetof(pt_regs, uregs[5]); break;
    case  6: ofs = offsetof(pt_regs, uregs[6]); break;
    case  7: ofs = offsetof(pt_regs, uregs[7]); break;
    case  8: ofs = offsetof(pt_regs, uregs[8]); break;
    case  9: ofs = offsetof(pt_regs, uregs[9]); break;
    case  10: ofs = offsetof(pt_regs, uregs[10]); break;
    case  11: ofs = offsetof(pt_regs, uregs[11]); break;
    case  12: ofs = offsetof(pt_regs, uregs[12]); break;
    case  13: ofs = offsetof(pt_regs, uregs[13]); break;
    case  14: ofs = offsetof(pt_regs, uregs[14]); break;
    case  15: ofs = offsetof(pt_regs, uregs[15]); break;
#elif defined(__aarch64__)
    case  0: ofs = offsetof(user_pt_regs, regs[0]); break;
    case  1: ofs = offsetof(user_pt_regs, regs[1]); break;
    case  2: ofs = offsetof(user_pt_regs, regs[2]); break;
    case  3: ofs = offsetof(user_pt_regs, regs[3]); break;
    case  4: ofs = offsetof(user_pt_regs, regs[4]); break;
    case  5: ofs = offsetof(user_pt_regs, regs[5]); break;
    case  6: ofs = offsetof(user_pt_regs, regs[6]); break;
    case  7: ofs = offsetof(user_pt_regs, regs[7]); break;
    case  8: ofs = offsetof(user_pt_regs, regs[8]); break;
    case  9: ofs = offsetof(user_pt_regs, regs[9]); break;
    case  10: ofs = offsetof(user_pt_regs, regs[10]); break;
    case  11: ofs = offsetof(user_pt_regs, regs[11]); break;
    case  12: ofs = offsetof(user_pt_regs, regs[12]); break;
    case  13: ofs = offsetof(user_pt_regs, regs[13]); break;
    case  14: ofs = offsetof(user_pt_regs, regs[14]); break;
    case  15: ofs = offsetof(user_pt_regs, regs[15]); break;
    case  16: ofs = offsetof(user_pt_regs, regs[16]); break;
    case  17: ofs = offsetof(user_pt_regs, regs[17]); break;
    case  18: ofs = offsetof(user_pt_regs, regs[18]); break;
    case  19: ofs = offsetof(user_pt_regs, regs[19]); break;
    case  20: ofs = offsetof(user_pt_regs, regs[20]); break;
    case  21: ofs = offsetof(user_pt_regs, regs[21]); break;
    case  22: ofs = offsetof(user_pt_regs, regs[22]); break;
    case  23: ofs = offsetof(user_pt_regs, regs[23]); break;
    case  24: ofs = offsetof(user_pt_regs, regs[24]); break;
    case  25: ofs = offsetof(user_pt_regs, regs[25]); break;
    case  26: ofs = offsetof(user_pt_regs, regs[26]); break;
    case  27: ofs = offsetof(user_pt_regs, regs[27]); break;
    case  28: ofs = offsetof(user_pt_regs, regs[28]); break;
    case  29: ofs = offsetof(user_pt_regs, regs[29]); break;
    case  30: ofs = offsetof(user_pt_regs, regs[30]); break;
    case  31: ofs = offsetof(user_pt_regs, sp); break;
#elif defined(__powerpc__)
    case   0: ofs = offsetof(pt_regs, gpr[0]); break;
    case   1: ofs = offsetof(pt_regs, gpr[1]); break;
    case   2: ofs = offsetof(pt_regs, gpr[2]); break;
    case   3: ofs = offsetof(pt_regs, gpr[3]); break;
    case   4: ofs = offsetof(pt_regs, gpr[4]); break;
    case   5: ofs = offsetof(pt_regs, gpr[5]); break;
    case   6: ofs = offsetof(pt_regs, gpr[6]); break;
    case   7: ofs = offsetof(pt_regs, gpr[7]); break;
    case   8: ofs = offsetof(pt_regs, gpr[8]); break;
    case   9: ofs = offsetof(pt_regs, gpr[9]); break;
    case  10: ofs = offsetof(pt_regs, gpr[10]); break;
    case  11: ofs = offsetof(pt_regs, gpr[11]); break;
    case  12: ofs = offsetof(pt_regs, gpr[12]); break;
    case  13: ofs = offsetof(pt_regs, gpr[13]); break;
    case  14: ofs = offsetof(pt_regs, gpr[14]); break;
    case  15: ofs = offsetof(pt_regs, gpr[15]); break;
    case  16: ofs = offsetof(pt_regs, gpr[16]); break;
    case  17: ofs = offsetof(pt_regs, gpr[17]); break;
    case  18: ofs = offsetof(pt_regs, gpr[18]); break;
    case  19: ofs = offsetof(pt_regs, gpr[19]); break;
    case  20: ofs = offsetof(pt_regs, gpr[20]); break;
    case  21: ofs = offsetof(pt_regs, gpr[21]); break;
    case  22: ofs = offsetof(pt_regs, gpr[22]); break;
    case  23: ofs = offsetof(pt_regs, gpr[23]); break;
    case  24: ofs = offsetof(pt_regs, gpr[24]); break;
    case  25: ofs = offsetof(pt_regs, gpr[25]); break;
    case  26: ofs = offsetof(pt_regs, gpr[26]); break;
    case  27: ofs = offsetof(pt_regs, gpr[27]); break;
    case  28: ofs = offsetof(pt_regs, gpr[28]); break;
    case  29: ofs = offsetof(pt_regs, gpr[29]); break;
    case  30: ofs = offsetof(pt_regs, gpr[30]); break;
    case  31: ofs = offsetof(pt_regs, gpr[31]); break;
    case  64: ofs = offsetof(pt_regs, ccr); break;
    case  66: ofs = offsetof(pt_regs, msr); break;
    case 101: ofs = offsetof(pt_regs, xer); break;
    case 108: ofs = offsetof(pt_regs, link); break;
    case 109: ofs = offsetof(pt_regs, ctr); break;
    case 118: ofs = offsetof(pt_regs, dsisr); break;
    case 119: ofs = offsetof(pt_regs, dar); break;
# if !defined(__powerpc64__)
    case 100: ofs = offsetof(pt_regs, mq); break;
# endif
    // ??? NIP is not assigned to a dwarf register number at all.
#elif defined(__s390__)
    case  0: ofs = offsetof(user_regs_struct, gprs[0]); break;
    case  1: ofs = offsetof(user_regs_struct, gprs[1]); break;
    case  2: ofs = offsetof(user_regs_struct, gprs[2]); break;
    case  3: ofs = offsetof(user_regs_struct, gprs[3]); break;
    case  4: ofs = offsetof(user_regs_struct, gprs[4]); break;
    case  5: ofs = offsetof(user_regs_struct, gprs[5]); break;
    case  6: ofs = offsetof(user_regs_struct, gprs[6]); break;
    case  7: ofs = offsetof(user_regs_struct, gprs[7]); break;
    case  8: ofs = offsetof(user_regs_struct, gprs[8]); break;
    case  9: ofs = offsetof(user_regs_struct, gprs[9]); break;
    case 10: ofs = offsetof(user_regs_struct, gprs[10]); break;
    case 11: ofs = offsetof(user_regs_struct, gprs[11]); break;
    case 12: ofs = offsetof(user_regs_struct, gprs[12]); break;
    case 13: ofs = offsetof(user_regs_struct, gprs[13]); break;
    case 14: ofs = offsetof(user_regs_struct, gprs[14]); break;
    case 15: ofs = offsetof(user_regs_struct, gprs[15]); break;
    // Note that the FPRs are not numbered sequentially
    case 16: ofs = offsetof(user_regs_struct, fp_regs.fprs[0]); break;
    case 17: ofs = offsetof(user_regs_struct, fp_regs.fprs[2]); break;
    case 18: ofs = offsetof(user_regs_struct, fp_regs.fprs[4]); break;
    case 19: ofs = offsetof(user_regs_struct, fp_regs.fprs[6]); break;
    case 20: ofs = offsetof(user_regs_struct, fp_regs.fprs[1]); break;
    case 21: ofs = offsetof(user_regs_struct, fp_regs.fprs[3]); break;
    case 22: ofs = offsetof(user_regs_struct, fp_regs.fprs[5]); break;
    case 23: ofs = offsetof(user_regs_struct, fp_regs.fprs[7]); break;
    case 24: ofs = offsetof(user_regs_struct, fp_regs.fprs[8]); break;
    case 25: ofs = offsetof(user_regs_struct, fp_regs.fprs[10]); break;
    case 26: ofs = offsetof(user_regs_struct, fp_regs.fprs[12]); break;
    case 27: ofs = offsetof(user_regs_struct, fp_regs.fprs[14]); break;
    case 28: ofs = offsetof(user_regs_struct, fp_regs.fprs[9]); break;
    case 29: ofs = offsetof(user_regs_struct, fp_regs.fprs[11]); break;
    case 30: ofs = offsetof(user_regs_struct, fp_regs.fprs[13]); break;
    case 31: ofs = offsetof(user_regs_struct, fp_regs.fprs[15]); break;
    // ??? Omitting CTRs (not in user_regs_struct)
    // ??? Omitting ACRs (lazy, and unlikely to appear in unwind)
    case 64: ofs = offsetof(user_regs_struct, psw.mask); break;
    case 65: ofs = offsetof(user_regs_struct, psw.addr); break;
#endif
    default:
      throw SEMANTIC_ERROR(_("unhandled register number"), e->tok);
    }

  value *frame = this_prog.lookup_reg (BPF_REG_10);
  this_prog.mk_binary (this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_3),
                       this_in_arg0, this_prog.new_imm (ofs));
  this_prog.mk_mov (this_ins, this_prog.lookup_reg(BPF_REG_2),
		    this_prog.new_imm (size));
  this_prog.mk_binary (this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_1),
		       frame, this_prog.new_imm (-size));
  this_prog.use_tmp_space(size);

  this_prog.mk_call(this_ins, BPF_FUNC_probe_read, 3);

  value *d = this_prog.new_reg ();
  int opc;
  switch (size)
    {
    case 4: opc = BPF_W; break;
    case 8: opc = BPF_DW; break;
    default:
      throw SEMANTIC_ERROR(_("unhandled register size"), e->tok);
    }
  this_prog.mk_ld (this_ins, opc, d, frame, -size);
  result = d;
}

// Emit unrolled-loop code to write string literal from src to
// dest[+ofs] in 4-byte chunks, with optional zero-padding up to
// BPF_MAXSTRINGLEN.
//
// ??? Could use 8-byte chunks if we're starved for instruction count.
// ??? Endianness of the target comes into play here.
value *
emit_simple_literal_str(program &this_prog, insn_inserter &this_ins,
                 value *dest, int ofs, const std::string &src, bool zero_pad)
{
#ifdef DEBUG_CODEGEN
  this_ins.notes.push("str");
#endif

  size_t str_bytes = src.size() + 1;
  size_t str_words = (str_bytes + 3) / 4;

  for (unsigned i = 0; i < str_words; ++i)
    {
      uint32_t word = 0;
      for (unsigned j = 0; j < 4; ++j)
        if (i * 4 + j < str_bytes - 1)
          {
            // ??? assuming little-endian target
            //
            // Must cast each signed char in src to unsigned char first
            // in order to avoid the implicit sign extension resulting 
            // from the uint32_t cast. 
            word |= ((uint32_t)(unsigned char)src[i * 4 + j]) << (j * 8);
          }

      this_prog.mk_st(this_ins, BPF_W,
                      dest, (int32_t)i * 4 + ofs,
                      this_prog.new_imm(word));
    }

  // XXX: bpf_map_update_elem and bpf_map_lookup_elem will always copy
  // exactly BPF_MAXSTRINGLEN bytes, which can cause problems with
  // garbage data beyond the end of the string, particularly for map
  // keys. The silliest way to solve this is by padding every string
  // constant to BPF_MAXSTRINGLEN bytes, but the stack isn't really
  // big enough for this to work with practical programs.
  //
  // So instead we have this optional code to pad the string, and
  // enable the option only when copying a string to a map key.
  if (zero_pad)
    {
      for (unsigned i = str_words; i < BPF_MAXSTRINGLEN / 4; i++)
        {
          this_prog.mk_st(this_ins, BPF_W,
                          dest, (int32_t)i * 4 + ofs,
                          this_prog.new_imm(0));
        }
    }

  value *out = this_prog.new_reg();
  this_prog.mk_binary(this_ins, BPF_ADD, out,
                      dest, this_prog.new_imm(ofs));

#ifdef DEBUG_CODEGEN
  this_ins.notes.pop(); // str
#endif
  return out;
}

// Emit unrolled-loop code to write string value from src to
// dest[+ofs] in 4-byte chunks, with optional zero-padding up to
// BPF_MAXSTRINGLEN.
//
// TODO (PR23860): This code does not work when the source and target
// regions overlap.
//
// ??? Could use 8-byte chunks if we're starved for instruction count.
// ??? Endianness of the target may come into play here.
value *
bpf_unparser::emit_string_copy(value *dest, int ofs, value *src, bool zero_pad)
{
  if (src->is_str())
    {
      /* If src is a string literal, its exact length is known and
         we can emit simpler, unconditional string copying code. */
      std::string str = src->str();
      return emit_simple_literal_str(this_prog, this_ins,
                                     dest, ofs, str, zero_pad);
    }

#ifdef DEBUG_CODEGEN
  this_ins.notes.push(zero_pad ? "strcpy_zero_pad" : "strcpy");
#endif

  size_t str_bytes = BPF_MAXSTRINGLEN;
  size_t str_words = (str_bytes + 3) / 4;

  value *out = this_prog.new_reg(); // -- where to store the final string addr
  block *return_block = this_prog.new_block();

  // XXX: It is sometimes possible to receive src == NULL.
  // trace_printk() did not care about being passed such values, but
  // applying strcpy() to NULL will (understandably) fail the
  // verifier. Therefore, we need to check for this possibility first:
  block *null_copy_block = this_prog.new_block();
  block *normal_block = this_prog.new_block();
  this_prog.mk_jcond(this_ins, EQ, src, this_prog.new_imm(0),
                     null_copy_block, normal_block);

  // Only call emit_simple_literal_str() if we can't reuse the zero-pad code:
  if (!zero_pad)
    {
      set_block(null_copy_block);
      value *empty_str = emit_simple_literal_str (this_prog, this_ins,
                                                  dest, ofs, "", false);
      emit_mov(out, empty_str);
      emit_jmp(return_block);
    }

  set_block(normal_block);

  /* block_A[i] copies src[4*i] to dest[4*i+ofs];
     block_B[i] copies 0 to dest[4*i+ofs], produced only if zero_pad is true. */
  std::vector<block *> block_A, block_B;
  block_A.push_back(this_ins.get_block());
  if (zero_pad) block_B.push_back(null_copy_block);

  for (unsigned i = 0; i < str_words; ++i)
    {
      block *next_block;
      if (i < str_words - 1)
        {
          /* Create block_A[i+1], block_B[i+1]: */
          block_A.push_back(this_prog.new_block());
          if (zero_pad) block_B.push_back(this_prog.new_block());
          next_block = block_A[i+1];
        }
      else
        {
          next_block = return_block;
        }

      set_block(block_A[i]);

      value *word = this_prog.new_reg();
      this_prog.mk_ld(this_ins, BPF_W, word,
                      src, (int32_t)i * 4);
      this_prog.mk_st(this_ins, BPF_W,
                      dest, (int32_t)i * 4 + ofs,
                      word);

      /* Finish unconditionally after copying BPF_MAXSTRINGLEN bytes: */
      if (i == str_words - 1)
        {
          emit_jmp(next_block);
          continue;
        }

      // Determining whether a word contains a NUL byte is a neat bit-fiddling puzzle.
      // Kudos go to Valgrind and Memcheck for showing the way, along the lines of:
      //
      //   b1 := word & 0xff; nz1 := (-b1)|b1; all_nz = nz1
      //   b2 := (word >> 8) & 0xff; nz2 := (-b2)|b2; all_nz = all_nz & nz2
      //   b3 := (word >> 16) & 0xff; nz3 := (-b3)|b3; all_nz = all_nz & nz3
      //   b4 := (word >> 24) & 0xff; nz4 := (-b4)|b4; all_nz = all_nz & nz4
      //   all_nz := nz1 & nz2 & nz3 & nz4
      //
      // Here, nzX is 0 iff bX is NUL, all_nz is 0 iff word contains a NUL byte.
      value *all_nz = this_prog.new_reg();
      value *bN = this_prog.new_reg();
      value *nZ = this_prog.new_reg();
      for (unsigned j = 0; j < 4; j++)
        {
          unsigned shift = 8*j;
          if (shift != 0)
            {
              this_prog.mk_binary(this_ins, BPF_RSH, bN, word, this_prog.new_imm(shift));
            }
          else
            {
              emit_mov(bN, word);
            }
          this_prog.mk_binary(this_ins, BPF_AND, bN, bN, this_prog.new_imm(0xff));
          this_prog.mk_unary(this_ins, BPF_NEG, nZ, bN);
          this_prog.mk_binary(this_ins, BPF_OR, nZ, nZ, bN);
          if (j == 0)
            {
              emit_mov(all_nz, nZ);
            }
          else
            {
              this_prog.mk_binary(this_ins, BPF_AND, all_nz, all_nz, nZ);
            }
        }

      this_prog.mk_jcond(this_ins, EQ, all_nz, this_prog.new_imm(0),
                         zero_pad ? block_B[i+1] : return_block, next_block);
    }

  // XXX: Zero-padding is only used under specific circumstances;
  // see the corresponding comment in emit_simple_literal_str().
  if (zero_pad)
    {
      for (unsigned i = 0; i < str_words; ++i)
        {
          set_block(block_B[i]);
          this_prog.mk_st(this_ins, BPF_W,
                          dest, (int32_t)i * 4 + ofs,
                          this_prog.new_imm(0));

          emit_jmp(i < str_words - 1 ? block_B[i+1] : return_block);
        }
    }

  set_block(return_block);

  this_prog.mk_binary(this_ins, BPF_ADD, out,
                      dest, this_prog.new_imm(ofs));

#ifdef DEBUG_CODEGEN
  this_ins.notes.pop(); // strcpy
#endif
  return out;
}

// Used for passing long arguments on the stack where an address is
// expected. Store val in a stack slot at offset ofs and store the
// stack address of val in arg.
void
bpf_unparser::emit_long_arg(value *arg, int ofs, value *val)
{
  value *frame = this_prog.lookup_reg(BPF_REG_10);
  this_prog.mk_st(this_ins, BPF_DW, frame, ofs, val);
  this_prog.mk_binary(this_ins, BPF_ADD, arg,
                      frame, this_prog.new_imm(ofs));
}

// Used for passing string arguments on the stack where an address is
// expected.  Zero-pad and copy str to the stack at offset ofs and
// store the stack address of str in arg.  Zero-padding is required
// since functions such as map_update_elem will expect a fixed-length
// value of BPF_MAXSTRINGLEN for string map keys.
void
bpf_unparser::emit_str_arg(value *arg, int ofs, value *str)
{
  value *frame = this_prog.lookup_reg(BPF_REG_10);
  value *out = emit_string_copy(frame, ofs, str, true /* zero pad */);
  emit_mov(arg, out);
}

value *
bpf_unparser::emit_functioncall (functiondecl *f, const std::vector<value *>& args)
{
  // Create a new map for the function's local variables.
  locals_map *locals = new_locals(f->locals);

  // Install locals in the map.
  unsigned n = args.size();
  for (unsigned i = 0; i < n; ++i)
    {
      const locals_map::value_type v (f->formal_args[i], args[i]);
      auto ok = locals->insert (v);
      assert (ok.second);
    }

  locals_map *old_locals = this_locals;
  this_locals = locals;

  block *join_block = this_prog.new_block ();
  value *retval = this_prog.new_reg ();

  func_calls.push_back (f);
  func_return.push_back (join_block);
  func_return_val.push_back (retval);
  emit_stmt (f->body);
  func_return_val.pop_back ();
  func_return.pop_back ();
  func_calls.pop_back ();

  if (in_block ())
    emit_jmp (join_block);
  set_block (join_block);

  this_locals = old_locals;
  delete locals;

  return retval;
}

void
bpf_unparser::visit_functioncall (functioncall *e)
{
  // ??? Function overloading isn't handled.
  if (e->referents.size () != 1)
    throw SEMANTIC_ERROR (_("unhandled function overloading"), e->tok);
  functiondecl *f = e->referents[0];

  // ??? For now, always inline the function call.
  for (auto i = func_calls.begin(); i != func_calls.end(); ++i)
    if (f == *i)
      throw SEMANTIC_ERROR (_("unhandled function recursion"), e->tok);

  // XXX: Should have been checked in earlier pass.
  assert (e->args.size () == f->formal_args.size ());

  // Evaluate and collect the function arguments.
  std::vector<value *> args;
  for (unsigned n = e->args.size (), i = 0; i < n; ++i)
    {
      value *r = this_prog.new_reg ();
      emit_mov (r, emit_expr (e->args[i]));
      args.push_back(r);
    }

  result = emit_functioncall(f, args);
}

int
globals::intern_string (std::string& str)
{
  if (interned_str_map.count(str) > 0)
    return interned_str_map[str];

  int this_idx = interned_strings.size();
  interned_strings.push_back(str);
  interned_str_map[str] = this_idx;
  return this_idx;
}

// Generates perf_event_output transport message glue code.
//
// XXX: Based on the interface of perf_event_output, this_in_arg0 must
// be a pt_regs * struct. In fact, the BPF program apparently has to
// pass the context given to the program as arg 0, regardless of the
// type. For the sake of user-space helpers (e.g. begin/end) we just
// pass NULL when this_in_arg0 is not available. Should not happen
// in-kernel where BPF programs apparently always have a context, but
// it's worth noting the assumptions here.
//
// TODO: We need to specify the transport message format more
// compactly. Thus far, everything is written as double-words to avoid
// getting 'misaligned stack access' errors from the verifier.
//
// TODO: We could extend this interface to allow passing multiple
// values in one transport message, e.g. a sequence of pe_long.
void
bpf_unparser::emit_transport_msg (globals::perf_event_type msg,
                                  value *arg, exp_type format_type)
{
  // Harmonize the information in arg, format_type, and msg:
  if (arg != NULL)
    {
      if (format_type == pe_unknown)
        format_type = arg->format_type;
      assert(format_type == arg->format_type || arg->format_type == pe_unknown);
      if (arg->is_str() && arg->is_format() && format_type == pe_unknown)
        format_type = pe_string;

      // XXX: Finally, pick format_type based on msg (inferred from format string):
      if (msg == globals::STP_PRINTF_ARG_LONG && format_type == pe_unknown)
        format_type = pe_long;
      else if (msg == globals::STP_PRINTF_ARG_STR && format_type == pe_unknown)
        format_type = pe_string;
    }

  unsigned arg_size = 0;
  if (arg != NULL)
    switch (format_type)
      {
      case pe_long:
        arg_size = 8;
        break;
      case pe_string:
        if (arg->is_str() && arg->is_format())
          arg_size = sizeof(BPF_TRANSPORT_ARG); // pass index of interned str
        else
          arg_size = BPF_MAXSTRINGLEN;
        break;
      default:
        assert(false); // XXX: Should be caught earlier.
      }

  // XXX: The following force-aligns all elements to double word boundary.
  // Could probably switch to single-word alignment with more careful design.
  if (arg_size % 8 != 0)
    arg_size += 8 - arg_size % 8;
  int arg_ofs = -arg_size;
  int msg_ofs = arg_ofs-sizeof(BPF_TRANSPORT_VAL);
  if (msg_ofs % 8 != 0)
    msg_ofs -= (8 - (-msg_ofs) % 8);
  this_prog.use_tmp_space(-msg_ofs);

  value *frame = this_prog.lookup_reg(BPF_REG_10);

  // store arg
  if (arg != NULL)
    switch (format_type)
      {
      case pe_long:
        this_prog.mk_st(this_ins, BPF_DW, frame, arg_ofs, arg);
        break;
      case pe_string:
        if (arg->is_str() && arg->is_format())
          {
            int idx = glob.intern_string(arg->str_val);
            this_prog.mk_st(this_ins, BPF_DW, frame, arg_ofs,
                            this_prog.new_imm(idx));
          }
        else
          emit_string_copy(frame, arg_ofs, arg, false /* no zero pad */);
        break;
      default:
        assert(false); // XXX: Should be caught earlier.
      }

  // double word -- XXX verifier forces aligned access
  this_prog.mk_st(this_ins, BPF_DW, frame, msg_ofs, this_prog.new_imm(msg));

  value *ctx = this_in_arg0 == NULL ? this_prog.new_imm(0) : this_in_arg0;
  emit_mov(this_prog.lookup_reg(BPF_REG_1), ctx); // ctx
  this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_2),
                     globals::perf_event_map_idx);
  emit_mov(this_prog.lookup_reg(BPF_REG_3),
           this_prog.new_imm(BPF_F_CURRENT_CPU)); // flags
  this_prog.mk_binary(this_ins, BPF_ADD,
                      this_prog.lookup_reg(BPF_REG_4),
                      frame, this_prog.new_imm(msg_ofs));
  emit_mov(this_prog.lookup_reg(BPF_REG_5), this_prog.new_imm(-msg_ofs));
  this_prog.mk_call(this_ins, BPF_FUNC_perf_event_output, 5);
}

globals::perf_event_type
printf_arg_type (value *arg, const print_format::format_component &c)
{
  switch (arg->format_type)
    {
    case pe_long:
      return globals::STP_PRINTF_ARG_LONG;
    case pe_string:
      return globals::STP_PRINTF_ARG_STR;
    case pe_unknown:
      // XXX: Could be a lot stricter and force
      // arg->format_type and c.type to match.
      switch (c.type) {
      case print_format::conv_pointer:
      case print_format::conv_number:
      case print_format::conv_char:
      case print_format::conv_memory:
      case print_format::conv_memory_hex:
      case print_format::conv_binary:
        return globals::STP_PRINTF_ARG_LONG;

      case print_format::conv_string:
        return globals::STP_PRINTF_ARG_STR;

      default:
        assert(false); // XXX
      }
    default:
      assert(false); // XXX: Should be caught earlier.
    }
}

value *
bpf_unparser::emit_print_format (const std::string& format,
                                 const std::vector<value *>& actual,
                                 bool print_to_stream,
                                 const token *tok)
{
  size_t nargs = actual.size();

  if (!print_to_stream)
    {
      // PR24528: Userspace-only feature.
      if (this_prog.target == target_kernel_bpf)
        throw SEMANTIC_ERROR(_("unsupported sprintf in bpf kernel probe"), tok);

      // TODO: sprintf() has an additional constraint on arguments due
      // to passing them in a very small number of registers.
      if (actual.size() > BPF_MAXSPRINTFARGS)
        throw SEMANTIC_ERROR(_NF("additional argument to sprintf",
                                 "too many arguments to sprintf (%zu)",
                                 actual.size(), actual.size()), tok);

      // Emit an ordinary function call to sprintf.
      size_t format_bytes = format.size() + 1;
      this_prog.mk_mov(this_ins, this_prog.lookup_reg(BPF_REG_1),
                       this_prog.new_str(format, true /*format_str*/));
      emit_mov(this_prog.lookup_reg(BPF_REG_2), this_prog.new_imm(format_bytes));
      for (size_t i = 0; i < nargs; ++i)
        emit_mov(this_prog.lookup_reg(BPF_REG_3 + i), actual[i]);

      this_prog.mk_call(this_ins, BPF_FUNC_sprintf, nargs + 2);
      return this_prog.lookup_reg(BPF_REG_0);
    }

  // Filter components to include only non-literal printf arguments:
  std::vector<print_format::format_component> all_components =
    print_format::string_to_components(format);
  // XXX: Could pass print_format * to avoid extra parse, except for embedded-code.

  std::vector<print_format::format_component> components;
  for (auto &c : all_components) {
    if (c.type != print_format::conv_literal)
      components.push_back(c);
  }
  if (components.size() != nargs)
    {
      if (tok != NULL)
        throw SEMANTIC_ERROR(_F("format string expected %zu args, got %zu",
                                components.size(), nargs), tok);
      else
        assert(false); // XXX: Should be caught earlier.
    }

  emit_transport_msg(globals::STP_PRINTF_START, this_prog.new_imm(nargs), pe_long);
  emit_transport_msg(globals::STP_PRINTF_FORMAT, this_prog.new_str(format, true /*format_str*/));
  for (size_t i = 0; i < nargs; ++i)
    emit_transport_msg(printf_arg_type(actual[i], components[i]), actual[i]);
  emit_transport_msg(globals::STP_PRINTF_END);

  return NULL;
}

void
bpf_unparser::visit_print_format (print_format *e)
{
  if (e->hist)
    throw SEMANTIC_ERROR (_("unhandled histogram print"), e->tok);

  size_t nargs = e->args.size();
  size_t i;
  if (nargs > BPF_MAXPRINTFARGS)
    throw SEMANTIC_ERROR(_NF("additional argument to print",
			     "too many arguments to print (%zu)",
			     e->args.size(), e->args.size()), e->tok);

  std::vector<value *> actual;
  for (i = 0; i < nargs; ++i)
    {
      value *arg = emit_expr(e->args[i]);
      arg->format_type = e->args[i]->type;
      actual.push_back(arg);
    }

  for (size_t i = 0; i < nargs; ++i)
    if (actual[i]->format_type == pe_stats)
      throw SEMANTIC_ERROR (_("cannot print a raw stats object"), e->args[i]->tok);
    else if (actual[i]->format_type != pe_long && actual[i]->format_type != pe_string)
      throw SEMANTIC_ERROR (_("cannot print unknown expression type"), e->args[i]->tok);

  std::string format;
  if (e->print_with_format)
    {
      // If this is a long string with no actual arguments, it will be
      // interned in the format string table as usual.
      interned_string fstr = e->raw_components;
      format += translate_escapes(fstr, e->tok);
    }
  else
    {
      // Synthesize a print-format string if the user didn't
      // provide one; the synthetic string simply contains one
      // directive for each argument.
      std::string delim;
      if (e->print_with_delim)
	{
	  interned_string dstr = e->delimiter;
	  for (interned_string::const_iterator j = dstr.begin();
	       j != dstr.end(); ++j)
	    {
	      if (*j == '%')
		delim += '%';
	      delim += *j;
	    }
	}

      for (i = 0; i < nargs; ++i)
	{
	  if (i > 0 && e->print_with_delim)
	    format += delim;
	  switch (e->args[i]->type)
	    {
	    default:
	    case pe_unknown:
	      throw SEMANTIC_ERROR(_("cannot print unknown expression type"),
				   e->args[i]->tok);
	    case pe_stats:
	      throw SEMANTIC_ERROR(_("cannot print a raw stats object"),
				   e->args[i]->tok);
	    case pe_long:
	      format += "%lld";
	      break;

	    case pe_string:
	      format += "%s";
	      break;
	    }
	}
      if (e->print_with_newline)
	format += '\n';
    }

  size_t format_bytes = format.size() + 1;
  if (format_bytes > BPF_MAXFORMATLEN)
    throw SEMANTIC_ERROR(_("Format string for print too long"), e->tok);

  value *retval = emit_print_format(format, actual, e->print_to_stream, e->tok);
  if (retval != NULL)
    result = retval;
}

void
bpf_unparser::visit_stat_op (stat_op* e)
{
#ifdef DEBUG_CODEGEN
  this_ins.notes.push("stat_get");
#endif

  // XXX PR24528: This code is userspace-only. Unfortunately, BPF does
  // not allow accessing percpu map elements from other cpus in
  // kernel-space, so for now we will just issue a fake helper call
  // and let the userspace sort this out.
  //
  // "I don't see a case where accessing other cpu per-cpu element
  // wouldn't be a bug in the program."
  // https://lore.kernel.org/patchwork/patch/634595/
  if (this_prog.target == target_kernel_bpf)
    throw SEMANTIC_ERROR(_("unsupported extraction function in bpf kernel probe"), e->tok);

  switch (e->ctype)
    {
    case sc_average:
    case sc_count:
    case sc_sum:
      break; // ok to pass to the helper

    case sc_none:
      assert (0); // should not happen, as sc_none is only used in foreach slots

    // TODO PR23476: Not yet implemented.
    case sc_min:
    case sc_max:
    case sc_variance:
    default:
      throw SEMANTIC_ERROR (_("unhandled stat op"), e->tok);
    }

  // identify the aggregate for the userspace interpreter
  globals::agg_idx agg = 0;

  if (symbol *s = dynamic_cast<symbol *>(e->stat)) // scalar stat value
    {
      vardecl *v = s->referent;
      assert (v->arity == 0);
      agg = 0; // id for scalar stat value

      if (v->type != pe_stats)
        throw SEMANTIC_ERROR (_("unexpected aggregate of non-statistic"), v->tok);

      auto g = glob.globals.find (v);
      if (g == glob.globals.end())
        throw SEMANTIC_ERROR(_("unknown statistics variable"), v->tok);
      if (!g->second.is_stat())
        throw SEMANTIC_ERROR(_("not a statistics variable"), v->tok);

      // Store the long on the stack and pass its address:
      emit_long_arg(this_prog.lookup_reg(BPF_REG_2), -8,
                    this_prog.new_imm(g->second.idx));
      this_prog.use_tmp_space(8);
    }
  else if (arrayindex *a = dynamic_cast<arrayindex *>(e->stat)) // array stat value
    {
      if (symbol *a_sym = dynamic_cast<symbol *>(a->base))
        {
          vardecl *v = a_sym->referent;
          agg = glob.aggregates[v]; // id for array stat value

	  auto g = glob.globals.find(v);
	  if (g == glob.globals.end())
	    throw SEMANTIC_ERROR(_("unknown array variable"), v->tok);

	  unsigned element = v->arity;
	  unsigned key_ofs = 0;

	  // iterate over the elements
	  do {
	    --element;
	    value *idx = emit_expr(a->indexes[element]);
            switch (v->index_types[element])
              {
              case pe_long:
                // Store the long on the stack and pass its address:
		key_ofs -= 8;
                emit_long_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
                break;
              case pe_string:
                // Zero-pad and copy the string to the stack and pass its address:
                key_ofs -= BPF_MAXSTRINGLEN;
                emit_str_arg(this_prog.lookup_reg(BPF_REG_2), key_ofs, idx);
                break;
              default:
                throw SEMANTIC_ERROR(_("unhandled index type"), v->tok);
              }
	  } while (element);
	  this_prog.use_tmp_space(-key_ofs);
        }
      else
        throw SEMANTIC_ERROR(_("unknown statistics value"), e->stat->tok);
    }

  emit_mov(this_prog.lookup_reg(BPF_REG_1), this_prog.new_imm(agg)); // agg_idx

  uint64_t sc_type = globals::intern_sc_type(e->ctype);
  emit_mov(this_prog.lookup_reg(BPF_REG_3), this_prog.new_imm(sc_type));

  this_prog.mk_call (this_ins, BPF_FUNC_stapbpf_stat_get, 3);

  result = this_prog.new_reg();
  emit_mov(result, this_prog.lookup_reg(BPF_REG_0));

#ifdef DEBUG_CODEGEN
  this_ins.notes.pop();
#endif
}

void
bpf_unparser::visit_hist_op (hist_op *e)
{
  // TODO PR24424: Implement as a perf-request or as a userspace-only helper.
  throw SEMANTIC_ERROR (_("unhandled hist op"), e->tok);
}

// } // anon namespace

void
build_internal_globals(globals& glob)
{
  struct vardecl exit;
  exit.name = "__global___STAPBPF_exit";
  exit.unmangled_name = "__STAPBPF_exit";
  exit.type = pe_long;
  exit.arity = 0;
  glob.internal_exit = exit;

  glob.globals.insert(std::pair<vardecl *, globals::map_slot>
                      (&glob.internal_exit,
                       globals::map_slot(0, globals::EXIT)));
  glob.maps.push_back
    ({ BPF_MAP_TYPE_HASH, 4, /* NB: value_size */ 8, globals::NUM_INTERNALS, 0 });

  // PR22330: Use a PERF_EVENT_ARRAY map for message transport:
  glob.maps.push_back
    ({ BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4, 4, globals::NUM_CPUS_PLACEHOLDER, 0 });
  // XXX: NUM_CPUS_PLACEHOLDER will be replaced at loading time.
}

static void
translate_globals (globals &glob, systemtap_session& s)
{
  int long_map = -1; // -- for scalar long variables
  int str_map = -1;  // -- for scalar string variables
  build_internal_globals(glob);

  for (auto i = s.globals.begin(); i != s.globals.end(); ++i)
    {
      vardecl *v = *i;
      int this_map, this_idx;

      switch (v->arity)
	{
	case 0: // scalars
	  switch (v->type)
	    {
	    case pe_long:
	      if (long_map < 0)
		{
		  globals::bpf_map_def m = {
		    BPF_MAP_TYPE_ARRAY, 4, 8, 0, 0
		  };
		  long_map = glob.maps.size();
		  glob.maps.push_back(m);
		}
	      this_map = long_map;
	      this_idx = glob.maps[long_map].max_entries++;
	      break;

            case pe_string:
              if (str_map < 0)
                {
                  globals::bpf_map_def m = {
                    BPF_MAP_TYPE_ARRAY, 4, BPF_MAXSTRINGLEN, 0, 0
                  };
                  str_map = glob.maps.size();
                  glob.maps.push_back(m);
                }
              this_map = str_map;
              this_idx = glob.maps[str_map].max_entries++;
              break;

            case pe_stats:
              if (glob.scalar_stats.empty())
                {
                  for (globals::stat_field f : globals::stat_fields)
                    {
                      globals::bpf_map_def m = {
                        BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 0, 0
                      };
                      globals::map_idx map_id = glob.maps.size();
                      glob.maps.push_back(m);
                      glob.scalar_stats[f] = map_id;
                    }
                  // ??? TODO: skip/drop any stat fields unused by all aggregates
                  // TODO PR24424: special case for 'histogram' field
                }
              this_map = -1; // Mark as statistical aggregate.

              // Add one element to each stat field's array:
              this_idx = -1;
              for (globals::stat_field f : globals::stat_fields)
                {
                  // XXX: Not all aggregates use the same stat
                  // fields. Some slots may therefore be unused, but
                  // it simplifies things a lot to use the same index
                  // for all fields of an aggregate.
                  int map_id = glob.scalar_stats[f];
                  int check_idx = glob.maps[map_id].max_entries++;
                  if (this_idx == -1)
                    this_idx = check_idx;
                  else
                    assert(check_idx == this_idx); // XXX: All arrays same length.
                }
              assert(this_idx >= 0);
              break;

	    default:
	      throw SEMANTIC_ERROR (_("unhandled scalar type"), v->tok);
	    }
	  break;

	default: // arrays (one or more dimension)
          {
            unsigned key_size = 0;
            unsigned max_entries;
	    unsigned element = v->arity;
	    do {
	      --element;
	      switch (v->index_types[element])
                {
		case pe_long:
		  key_size += 8;
		  break;
                case pe_string:
                  key_size += BPF_MAXSTRINGLEN;
                  break;
                default:
                  throw SEMANTIC_ERROR (_("unhandled index type"), v->tok);
                }
	    } while (element);
            max_entries = v->maxsize > 0 ? v->maxsize : BPF_MAXMAPENTRIES;

            if (v->type == pe_stats)
              {
                glob.array_stats[v] = globals::stats_map();
                for (globals::stat_field f : globals::stat_fields)
                  {
                    globals::bpf_map_def m = {
                      BPF_MAP_TYPE_PERCPU_HASH, 0, 0, 0, 0
                    };
                    m.key_size = key_size;
                    m.max_entries = max_entries;
                    m.value_size = 8; // XXX: for stat data, sizeof(uint64_t)
                    int map_id = glob.maps.size();
                    glob.maps.push_back(m);
                    glob.array_stats[v][f] = map_id;

                    // Assign an agg_idx to identify the aggregate from BPF code.
                    // XXX: agg_idx 0 is reserved for scalar_stats:
                    glob.aggregates[v] = 1 + glob.aggregates.size();

                    // ??? TODO: skip/drop any stat fields unused by this aggregate
                    // TODO PR24424: special case for 'histogram' field
                  }

                this_map = -1; // Mark as statistical aggregate.
                this_idx = -1; // Mark as array.
              }
            else
              {
                globals::bpf_map_def m = { BPF_MAP_TYPE_HASH, 0, 0, 0, 0 };
                m.key_size = key_size;

                switch (v->type)
                  {
                  case pe_long:
                    m.value_size = 8;
                    break;
                  case pe_string:
                    m.value_size = BPF_MAXSTRINGLEN;
                    break;
                  // XXX: case pe_stats is handled above
                  default:
                    throw SEMANTIC_ERROR (_("unhandled array element type"), v->tok);
                  }

                m.max_entries = max_entries;
                this_map = glob.maps.size();
                glob.maps.push_back(m);
                this_idx = -1; // XXX: was 0, check if this is used correctly
              }
          }
	  break;
	}

      assert(this_map != globals::internal_map_idx);
      auto ok = (glob.globals.insert
		 (std::pair<vardecl *, globals::map_slot>
		  (v, globals::map_slot(this_map, this_idx))));
      assert(ok.second);
    }
}

struct BPF_Section
{
  Elf_Scn *scn;
  Elf64_Shdr *shdr;
  std::string name;
  Stap_Strent *name_ent;
  Elf_Data *data;
  bool free_data; // NB: then data must have been malloc()'d!

  BPF_Section(const std::string &n);
  ~BPF_Section();
};

BPF_Section::BPF_Section(const std::string &n)
  : scn(0), name(n), name_ent(0), data(0), free_data(false)
{ }

BPF_Section::~BPF_Section()
{
  if (free_data)
    free(data->d_buf);
}

struct BPF_Symbol
{
  std::string name;
  Stap_Strent *name_ent;
  Elf64_Sym sym;

  BPF_Symbol(const std::string &n, BPF_Section *, long);
};

BPF_Symbol::BPF_Symbol(const std::string &n, BPF_Section *sec, long off)
  : name(n), name_ent(0)
{
  memset(&sym, 0, sizeof(sym));
  sym.st_shndx = elf_ndxscn(sec->scn);
  sym.st_value = off;
}

struct BPF_Output
{
  Elf *elf;
  Elf64_Ehdr *ehdr;
  Stap_Strtab *str_tab;

  std::vector<BPF_Section *> sections;
  std::vector<BPF_Symbol *> symbols;

  BPF_Output(int fd);
  ~BPF_Output();
  BPF_Section *new_scn(const std::string &n);
  BPF_Symbol *new_sym(const std::string &n, BPF_Section *, long);
  BPF_Symbol *append_sym(const std::string &n, BPF_Section *, long);
};

BPF_Output::BPF_Output(int fd)
  : elf(elf_begin(fd, ELF_C_WRITE_MMAP, NULL)),
    ehdr(elf64_newehdr(elf)),
    str_tab(stap_strtab_init(true))
{
  ehdr->e_type = ET_REL;
  ehdr->e_machine = EM_BPF;
}

BPF_Output::~BPF_Output()
{
  stap_strtab_free(str_tab);

  for (auto i = symbols.begin(); i != symbols.end(); ++i)
    delete *i;
  for (auto i = sections.begin(); i != sections.end(); ++i)
    delete *i;

  elf_end(elf);
}

BPF_Section *
BPF_Output::new_scn(const std::string &name)
{
  BPF_Section *n = new BPF_Section(name);
  Elf_Scn *scn = elf_newscn(elf);

  n->scn = scn;
  n->shdr = elf64_getshdr(scn);
  n->data = elf_newdata(scn);
  n->name_ent = stap_strtab_add(str_tab, n->name.c_str());

  sections.push_back(n);
  return n;
}

BPF_Symbol *
BPF_Output::new_sym(const std::string &name, BPF_Section *sec, long off)
{
  BPF_Symbol *s = new BPF_Symbol(name, sec, off);
  s->name_ent = stap_strtab_add(str_tab, s->name.c_str());
  return s;
}

BPF_Symbol *
BPF_Output::append_sym(const std::string &name, BPF_Section *sec, long off)
{
  BPF_Symbol *s = new_sym(name, sec, off);
  symbols.push_back(s);
  return s;
}

static void
output_kernel_version(BPF_Output &eo, const std::string &base_version)
{
  unsigned long maj = 0, min = 0, rel = 0;
  char *q;

  maj = strtoul(base_version.c_str(), &q, 10);
  if (*q == '.')
    {
      min = strtoul(q + 1, &q, 10);
      if (*q == '.')
	rel = strtoul(q + 1, NULL, 10);
    }

  BPF_Section *so = eo.new_scn("version");
  Elf_Data *data = so->data;
  data->d_buf = malloc(sizeof(uint32_t));
  assert (data->d_buf);
  * (uint32_t*) data->d_buf = KERNEL_VERSION(maj, min, rel);
  data->d_type = ELF_T_BYTE;
  data->d_size = 4;
  data->d_align = 4;
  so->free_data = true;
  so->shdr->sh_type = SHT_PROGBITS;
  so->shdr->sh_entsize = 4;
}

static void
output_license(BPF_Output &eo)
{
  BPF_Section *so = eo.new_scn("license");
  Elf_Data *data = so->data;
  data->d_buf = (void *)"GPL";
  data->d_type = ELF_T_BYTE;
  data->d_size = 4;
  so->shdr->sh_type = SHT_PROGBITS;
}

static void
output_stapbpf_script_name(BPF_Output &eo, const std::string script_name)
{
  BPF_Section *so = eo.new_scn("stapbpf_script_name");
  Elf_Data *data = so->data;
  size_t script_name_len = strlen(script_name.c_str());
  data->d_buf = (void *)malloc(script_name_len + 1);
  char *script_name_buf = (char *)data->d_buf;
  script_name.copy(script_name_buf, script_name_len);
  script_name_buf[script_name_len] = '\0';
  data->d_type = ELF_T_BYTE;
  data->d_size = script_name_len + 1;
  so->free_data = true;
  so->shdr->sh_type = SHT_PROGBITS;
}

static void
output_maps(BPF_Output &eo, globals &glob)
{
  unsigned nmaps = glob.maps.size();
  if (nmaps == 0)
    return;

  assert(sizeof(unsigned) == sizeof(Elf64_Word));

  const size_t bpf_map_def_sz = sizeof(globals::bpf_map_def);
  BPF_Section *so = eo.new_scn("maps");
  Elf_Data *data = so->data;
  data->d_buf = glob.maps.data();
  data->d_type = ELF_T_BYTE;
  data->d_size = nmaps * bpf_map_def_sz;
  data->d_align = 4;
  so->shdr->sh_type = SHT_PROGBITS;
  so->shdr->sh_entsize = bpf_map_def_sz;

  // Allow the global arrays to have their actual names.
  eo.symbols.reserve(nmaps);
  for (unsigned i = 0; i < nmaps; ++i)
    eo.symbols.push_back(NULL);

  for (auto i = glob.globals.begin(); i != glob.globals.end(); ++i)
    {
      vardecl *v = i->first;
      if (v->arity <= 0)
	continue;
      if (i->second.is_stat())
        continue;
      unsigned m = i->second.map_id;
      assert(eo.symbols[m] == NULL);

      BPF_Symbol *s = eo.new_sym(v->name, so, m * bpf_map_def_sz);
      s->sym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_OBJECT);
      s->sym.st_size = bpf_map_def_sz;
      eo.symbols[m] = s;
    }

  // Give internal names to stat maps.
  for (auto i = glob.scalar_stats.begin(); i != glob.scalar_stats.end(); ++i)
    {
      std::string f = i->first;
      unsigned m = i->second;
      assert(eo.symbols[m] == NULL);

      BPF_Symbol *s = eo.new_sym(std::string("stat.") + f,
                                 so, m * bpf_map_def_sz);
      s->sym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_OBJECT);
      eo.symbols[m] = s;
    }
  for (auto i = glob.array_stats.begin(); i != glob.array_stats.end(); ++i)
    {
      vardecl *v = i->first;
      for (auto j = i->second.begin(); j != i->second.end(); ++j)
        {
          std::string f = j->first;
          unsigned m = j->second;
          assert(eo.symbols[m] == NULL);

          BPF_Symbol *s = eo.new_sym(std::string(v->name) + std::string(".stat.") + f,
                                     so, m * bpf_map_def_sz);
          s->sym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_OBJECT);
          eo.symbols[m] = s;
        }
    }

  // Give internal names to other maps.
  for (unsigned i = 0; i < nmaps; ++i)
    {
      if (eo.symbols[i] != NULL)
	continue;

      BPF_Symbol *s = eo.new_sym(std::string("map.") + std::to_string(i),
				 so, i * bpf_map_def_sz);
      s->sym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_OBJECT);
      s->sym.st_size = bpf_map_def_sz;
      eo.symbols[i] = s;
    }
}

static void
output_interned_strings(BPF_Output &eo, globals& glob)
{
  // XXX: Don't use SHT_STRTAB since it can reorder the strings, iiuc
  // requiring us to use yet more ELF infrastructure to refer to them
  // and forcing us to generate this section at the same time as the
  // code instead of in a separate procedure. To avoid that, manually
  // write a SHT_PROGBITS section in SHT_STRTAB format.

  if (glob.interned_strings.size() == 0)
    return;

  BPF_Section *str = eo.new_scn("stapbpf_interned_strings");
  Elf_Data *data = str->data;
  size_t interned_strings_len = 1; // extra NUL byte
  for (auto i = glob.interned_strings.begin();
       i != glob.interned_strings.end(); ++i)
    {
      std::string &str = *i;
      interned_strings_len += str.size() + 1; // with NUL byte
    }
  data->d_buf = (void *)malloc(interned_strings_len);
  char *interned_strings_buf = (char *)data->d_buf;
  interned_strings_buf[0] = '\0';
  unsigned ofs = 1;
  for (auto i = glob.interned_strings.begin();
       i != glob.interned_strings.end(); ++i)
    {
      std::string &str = *i;
      assert(ofs+str.size()+1 <= interned_strings_len);
      str.copy(interned_strings_buf+ofs, str.size());
      interned_strings_buf[ofs+str.size()] = '\0';
      ofs += str.size() + 1;
    }
  assert(ofs == interned_strings_len);
  data->d_type = ELF_T_BYTE;
  data->d_size = interned_strings_len;
  str->free_data = true;
  str->shdr->sh_type = SHT_PROGBITS;
}

static void
output_statsmap(void *d_buf, globals::agg_idx agg_id, const globals::stats_map &sm)
{
  globals::interned_stats_map ism = globals::intern_stats_map(sm);
  uint64_t *ix = (uint64_t *)d_buf;
  *ix = (uint64_t)agg_id;
  for (unsigned i = 0; i < globals::stat_fields.size(); i++)
    {
      globals::stat_field sf = globals::stat_fields[i];
      auto it = sm.find(sf);
      assert (it != sm.end());
      ix++; *ix = (uint64_t)it->second;
    }
}

static void
output_interned_aggregates(BPF_Output &eo, globals& glob)
{
  if (glob.scalar_stats.empty() && glob.aggregates.size() == 0)
    return;

  BPF_Section *agg = eo.new_scn("stapbpf_aggregates");
  Elf_Data *data = agg->data;
  size_t interned_aggregate_len =
    sizeof(uint64_t) * (1 + globals::stat_fields.size());
  unsigned n_aggregates =
    glob.scalar_stats.empty() ? glob.aggregates.size() : glob.aggregates.size() + 1;
  data->d_buf = (void *)calloc(n_aggregates, interned_aggregate_len);
  data->d_size = interned_aggregate_len * n_aggregates;
  size_t ofs = 0; // XXX after glob.scalar_stats
  if (!glob.scalar_stats.empty())
    {
      output_statsmap(data->d_buf, ofs, glob.scalar_stats);
      ofs += interned_aggregate_len;
    }
  char *ix = (char *)data->d_buf;
  for (auto i = glob.aggregates.begin();
       i != glob.aggregates.end(); i++)
    {
      assert(glob.array_stats.count(i->first) != 0);
      output_statsmap((void *)(ix+ofs), i->second, glob.array_stats[i->first]);
      ofs += interned_aggregate_len;
    }
  assert (ofs == data->d_size);
  data->d_type = ELF_T_BYTE;
  agg->free_data = true;
  agg->shdr->sh_type = SHT_PROGBITS;
}

void
bpf_unparser::add_prologue()
{
  value *i0 = this_prog.new_imm(0);

  // lookup exit global
  value *frame = this_prog.lookup_reg(BPF_REG_10);
  this_prog.mk_st(this_ins, BPF_W, frame, -4, i0);
  this_prog.use_tmp_space(4);

  this_prog.load_map(this_ins, this_prog.lookup_reg(BPF_REG_1),
                     globals::internal_map_idx);
  this_prog.mk_binary(this_ins, BPF_ADD, this_prog.lookup_reg(BPF_REG_2),
                      frame, this_prog.new_imm(-4));
  this_prog.mk_call(this_ins, BPF_FUNC_map_lookup_elem, 2);

  value *r0 = this_prog.lookup_reg(BPF_REG_0);
  block *cont_block = this_prog.new_block();
  block *exit_block = get_exit_block();

  // check that map_lookup_elem returned non-null ptr
  this_prog.mk_jcond(this_ins, EQ, r0, i0, exit_block, cont_block);
  set_block(cont_block);

  // load exit status from ptr
  value *exit_status = this_prog.new_reg();
  this_prog.mk_ld(this_ins, BPF_DW, exit_status, r0, 0);

  // if exit_status == 1 jump to exit, else continue with handler
  cont_block = this_prog.new_block();
  this_prog.mk_jcond(this_ins, EQ, exit_status, this_prog.new_imm(1),
                     exit_block, cont_block);
  set_block(cont_block);
}

static void
translate_probe(program &prog, globals &glob, derived_probe *dp)
{
  bpf_unparser u(prog, glob);
  u.this_locals = u.new_locals(dp->locals);

  u.set_block(prog.new_block ());

  // Save the input argument early.
  // ??? Ideally this would be deleted as dead code if it were unused;
  // we don't implement that at the moment.  Nor is it easy to support
  // inserting a new start block that would enable retroactively saving
  // this only when needed.
  u.this_in_arg0 = prog.lookup_reg(BPF_REG_6);
  prog.mk_mov(u.this_ins, u.this_in_arg0, prog.lookup_reg(BPF_REG_1));

  u.add_prologue();

  dp->body->visit (&u);

  if (u.in_block())
    u.emit_jmp(u.get_ret0_block());
}

static void
translate_probe_v(program &prog, globals &glob,
		  const std::vector<derived_probe *> &v)
{
  bpf_unparser u(prog, glob);
  block *this_block;

  if (prog.blocks.empty())
    this_block = prog.new_block();
  else
    {
      u.set_block(prog.blocks.back());
      this_block = prog.new_block();
      u.emit_jmp(this_block);
    }

  for (size_t n = v.size(), i = 0; i < n; ++i)
    {
      u.set_block(this_block);

      derived_probe *dp = v[i];
      u.this_locals = u.new_locals(dp->locals);
      dp->body->visit (&u);
      delete u.this_locals;
      u.this_locals = NULL;

      if (i == n - 1)
	this_block = u.get_ret0_block();
      else
	this_block = prog.new_block();
      if (u.in_block())
	u.emit_jmp(this_block);
    }
}

static void
translate_init_and_probe_v(program &prog, globals &glob, init_block &b,
                     const std::vector<derived_probe *> &v)
{
  bpf_unparser u(prog, glob);
  block *this_block = prog.new_block();

  u.set_block(this_block);
  b.visit(&u);

  if (!v.empty())
    translate_probe_v(prog, glob, v);
  else
    {
      this_block = u.get_ret0_block();
      assert(u.in_block());
      u.emit_jmp(this_block);
    }
}

static BPF_Section *
output_probe(BPF_Output &eo, program &prog,
	     const std::string &name, unsigned flags)
{
  unsigned ninsns = 0, nreloc = 0;

  // Count insns and relocations; drop in jump offset.
  for (auto i = prog.blocks.begin(); i != prog.blocks.end(); ++i)
    {
      block *b = *i;

      for (insn *j = b->first; j != NULL; j = j->next)
	{
	  unsigned code = j->code;
	  if ((code & 0xff) == (BPF_LD | BPF_IMM | BPF_DW))
	    {
	      if (code == BPF_LD_MAP)
		nreloc += 1;
	      ninsns += 2;
	    }
	  else
	    {
	      if (j->is_jmp())
                {
                  // ??? Forwarders should be removed by bpf-opt.cxx thread_jumps,
                  // but we seem to miss or reintroduce a few. Minimal fix:
                  block *target = b->taken->next;
                  while (target->first == NULL)
                    {
                      target = target->is_forwarder();
                      assert (target != NULL);
                    }

                  j->off = target->first->id - (j->id + 1);
                }
	      else if (j->is_call())
		j->off = 0;
	      ninsns += 1;
	    }
	}
    }

  bpf_insn *buf = (bpf_insn*) calloc (sizeof(bpf_insn), ninsns);
  assert (buf);
  Elf64_Rel *rel = (Elf64_Rel*) calloc (sizeof(Elf64_Rel), nreloc);
  assert (rel);

  unsigned i = 0, r = 0;
  for (auto bi = prog.blocks.begin(); bi != prog.blocks.end(); ++bi)
    {
      block *b = *bi;

      for (insn *j = b->first; j != NULL; j = j->next)
	{
	  unsigned code = j->code;
	  value *d = j->dest;
	  value *s = j->src1;

	  if (code == BPF_LD_MAP)
	    {
	      unsigned val = s->imm();

	      // Note that we arrange for the map symbols to be first.
	      rel[r].r_offset = i * sizeof(bpf_insn);
	      rel[r].r_info = ELF64_R_INFO(val + 1, R_BPF_MAP_FD);
	      r += 1;

	      buf[i + 0].code = code;
	      buf[i + 0].dst_reg = d->reg();
	      buf[i + 0].src_reg = code >> 8;
	      i += 2;
	    }
	  else if (code == (BPF_LD | BPF_IMM | BPF_DW))
	    {
	      uint64_t val = s->imm();
	      buf[i + 0].code = code;
	      buf[i + 0].dst_reg = d->reg();
	      buf[i + 0].src_reg = code >> 8;
	      buf[i + 0].imm = val;
	      buf[i + 1].imm = val >> 32;
	      i += 2;
	    }
	  else
	    {
	      buf[i].code = code;
	      if (!d)
		d = j->src0;
	      if (d)
		buf[i].dst_reg = d->reg();
	      if (s)
		{
		  if (s->is_reg())
		    buf[i].src_reg = s->reg();
		  else
		    buf[i].imm = s->imm();
		}
	      buf[i].off = j->off;
	      i += 1;
	    }
	}
    }
  assert(i == ninsns);
  assert(r == nreloc);

  BPF_Section *so = eo.new_scn(name);
  Elf_Data *data = so->data;
  data->d_buf = buf;
  data->d_type = ELF_T_BYTE;
  data->d_size = ninsns * sizeof(bpf_insn);
  data->d_align = 8;
  so->free_data = true;
  so->shdr->sh_type = SHT_PROGBITS;
  so->shdr->sh_flags = SHF_EXECINSTR | flags;

  if (nreloc)
    {
      BPF_Section *ro = eo.new_scn(std::string(".rel.") + name);
      Elf_Data *rdata = ro->data;
      rdata->d_buf = rel;
      rdata->d_type = ELF_T_REL;
      rdata->d_size = nreloc * sizeof(Elf64_Rel);
      ro->free_data = true;
      ro->shdr->sh_type = SHT_REL;
      ro->shdr->sh_info = elf_ndxscn(so->scn);
    }

  return so;
}

static void
output_symbols_sections(BPF_Output &eo)
{
  BPF_Section *str = eo.new_scn(".strtab");
  str->shdr->sh_type = SHT_STRTAB;
  str->shdr->sh_entsize = 1;

  unsigned nsym = eo.symbols.size();
  unsigned isym = 0;
  if (nsym > 0)
    {
      BPF_Section *sym = eo.new_scn(".symtab");
      sym->shdr->sh_type = SHT_SYMTAB;
      sym->shdr->sh_link = elf_ndxscn(str->scn);
      sym->shdr->sh_info = nsym + 1;

      Elf64_Sym *buf = new Elf64_Sym[nsym + 1];
      memset(buf, 0, sizeof(Elf64_Sym));

      sym->data->d_buf = buf;
      sym->data->d_type = ELF_T_SYM;
      sym->data->d_size = (nsym + 1) * sizeof(Elf64_Sym);

      stap_strtab_finalize(eo.str_tab, str->data);

      for (unsigned i = 0; i < nsym; ++i)
	{
	  BPF_Symbol *s = eo.symbols[i];
	  Elf64_Sym *b = buf + (i + 1);
	  *b = s->sym;
	  b->st_name = stap_strent_offset(s->name_ent);
	}

      isym = elf_ndxscn(sym->scn);
    }
  else
    stap_strtab_finalize(eo.str_tab, str->data);

  eo.ehdr->e_shstrndx = elf_ndxscn(str->scn);

  for (auto i = eo.sections.begin(); i != eo.sections.end(); ++i)
    {
      BPF_Section *s = *i;
      s->shdr->sh_name = stap_strent_offset(s->name_ent);
      if (s->shdr->sh_type == SHT_REL)
	s->shdr->sh_link = isym;
    }
}

} // namespace bpf

int
translate_bpf_pass (systemtap_session& s)
{
  using namespace bpf;

  init_bpf_helper_tables();

  if (elf_version(EV_CURRENT) == EV_NONE)
    return 1;

  module_name = s.module_name;
  const std::string module = s.tmpdir + "/" + s.module_filename();
  int fd = open(module.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd < 0)
    return 1;

  BPF_Output eo(fd);
  globals glob; glob.session = &s;
  int ret = 0;
  const token* t = 0;
  try
    {
      translate_globals(glob, s);
      output_maps(eo, glob);

      if (s.be_derived_probes || !glob.empty())
        {
          std::vector<derived_probe *> begin_v, end_v;
          sort_for_bpf(s, s.be_derived_probes, begin_v, end_v);
          init_block init(glob);

          if (!init.empty())
            {
              if (!begin_v.empty())
                t = begin_v[0]->tok;

              program p(target_user_bpfinterp);
              translate_init_and_probe_v(p, glob, init, begin_v);
              p.generate();
              output_probe(eo, p, "stap_begin", 0);
            }
          else if (!begin_v.empty())
            {
              t = begin_v[0]->tok;
              program p(target_user_bpfinterp);
              translate_probe_v(p, glob, begin_v);
              p.generate();
              output_probe(eo, p, "stap_begin", 0);
            }

          if (!end_v.empty())
            {
              t = end_v[0]->tok;
              program p(target_user_bpfinterp);
              translate_probe_v(p, glob, end_v);
              p.generate();
              output_probe(eo, p, "stap_end", 0);
            }
        }

      if (s.generic_kprobe_derived_probes)
        {
          sort_for_bpf_probe_arg_vector kprobe_v;
          sort_for_bpf(s, s.generic_kprobe_derived_probes, kprobe_v);

          for (auto i = kprobe_v.begin(); i != kprobe_v.end(); ++i)
            {
              t = i->first->tok;
              program p(target_kernel_bpf);
              translate_probe(p, glob, i->first);
              p.generate();
              output_probe(eo, p, i->second, SHF_ALLOC);
            }
        }

      if (s.procfs_derived_probes)
        {  
          sort_for_bpf_probe_arg_vector procfs_v;
          sort_for_bpf(s, s.procfs_derived_probes, procfs_v);

          for (auto i = procfs_v.begin(); i != procfs_v.end(); ++i) 
            {
              t = i->first->tok;
              program p(target_user_bpfinterp);
              translate_probe(p, glob, i->first); 
              p.generate();
              output_probe(eo, p, i->second, 0);
            }
        }

      if (s.perf_derived_probes)
        {
          sort_for_bpf_probe_arg_vector perf_v;
          sort_for_bpf(s, s.perf_derived_probes, perf_v);

          for (auto i = perf_v.begin(); i != perf_v.end(); ++i)
            {
              t = i->first->tok;
              program p(target_kernel_bpf);
              translate_probe(p, glob, i->first);
              p.generate();
              output_probe(eo, p, i->second, SHF_ALLOC);
            }
        }

      if (s.hrtimer_derived_probes || s.timer_derived_probes)
        {
          sort_for_bpf_probe_arg_vector timer_v;
          sort_for_bpf(s, s.hrtimer_derived_probes,
                       s.timer_derived_probes, timer_v);

          for (auto i = timer_v.begin(); i != timer_v.end(); ++i)
            {
              t = i->first->tok;
              // TODO PR23477: Also support userspace timer probes.
              program p(target_kernel_bpf);
              translate_probe(p, glob, i->first);
              p.generate();
              output_probe(eo, p, i->second, SHF_ALLOC);
            }
        }

      if (s.tracepoint_derived_probes)
        {
          sort_for_bpf_probe_arg_vector trace_v;
          sort_for_bpf(s, s.tracepoint_derived_probes, trace_v);

          for (auto i = trace_v.begin(); i != trace_v.end(); ++i)
            {
              t = i->first->tok;
              program p(target_kernel_bpf);
              translate_probe(p, glob, i->first);
              p.generate();
              output_probe(eo, p, i->second, SHF_ALLOC);
            }
        }

      if (s.uprobe_derived_probes)
        {
          sort_for_bpf_probe_arg_vector uprobe_v;
          sort_for_bpf(s, s.uprobe_derived_probes, uprobe_v);

          for (auto i = uprobe_v.begin(); i != uprobe_v.end(); ++i)
            {
              t = i->first->tok;
              program p(target_kernel_bpf);
              translate_probe(p, glob, i->first);
              p.generate();
              output_probe(eo, p, i->second, SHF_ALLOC);
            }
        }

      output_kernel_version(eo, s.kernel_base_release);
      output_license(eo);
      output_stapbpf_script_name(eo, escaped_literal_string(s.script_basename()));
      output_interned_strings(eo, glob);
      output_interned_aggregates(eo, glob);
      output_symbols_sections(eo);

      int64_t r = elf_update(eo.elf, ELF_C_WRITE_MMAP);
      if (r < 0)
	{
	  std::clog << "Error writing output file: "
		    << elf_errmsg(elf_errno()) << std::endl;
	  ret = 1;
	}
    }
  catch (const semantic_error &e)
    {
      s.print_error(e);
      ret = 1;
    }
  catch (const std::runtime_error &e)
    {
      semantic_error er(ERR_SRC, _F("bpf translation failure: %s", e.what()), t);
      s.print_error(er);
      ret = 1;
    }
  catch (...)
    {
      std::cerr << "bpf translation internal error" << std::endl;
      ret = 1;
    }

  close(fd);
  if (ret == 1)
    unlink(s.translated_source.c_str());
  return ret;
}
