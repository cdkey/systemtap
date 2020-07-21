// -*- C++ -*-
// Copyright (C) 2005-2019 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#ifndef TAPSETS_H
#define TAPSETS_H

#include "config.h"
#include "staptree.h"
#include "elaborate.h"
#include "stringtable.h"
#include "dwflpp.h"

void check_process_probe_kernel_support(systemtap_session& s);

void register_standard_tapsets(systemtap_session& sess);
std::vector<derived_probe_group*> all_session_groups(systemtap_session& s);
std::string common_probe_init (derived_probe* p);
void common_probe_entryfn_prologue (systemtap_session& s, std::string statestr,
                                    std::string statestr2,
				    std::string probe, std::string probe_type,
				    bool overload_processing = true,
				    void (*declaration_callback)(systemtap_session& s, void* data) = NULL,
				    void (*pre_context_callback)(systemtap_session& s, void* data) = NULL,
				    void* callback_data = NULL);
void common_probe_entryfn_epilogue (systemtap_session& s,
				    bool overload_processing,
				    bool schedule_work_safe);

struct be_derived_probe_group;
bool sort_for_bpf(systemtap_session& s,
		  be_derived_probe_group *,
		  std::vector<derived_probe *> &begin_v,
		  std::vector<derived_probe *> &end_v,
                  std::vector<derived_probe *> &error_v);

struct generic_kprobe_derived_probe_group;
struct uprobe_derived_probe_group;
struct perf_derived_probe_group;
struct hrtimer_derived_probe_group;
struct timer_derived_probe_group;
struct tracepoint_derived_probe_group;

struct hwbkpt_derived_probe_group;
struct utrace_derived_probe_group;
struct itrace_derived_probe_group;
struct netfilter_derived_probe_group;
struct profile_derived_probe_group;
struct mark_derived_probe_group;
struct python_derived_probe_group;

typedef std::vector<std::pair<derived_probe *, std::string> >
  sort_for_bpf_probe_arg_vector;

bool sort_for_bpf(systemtap_session& s,
		  generic_kprobe_derived_probe_group *ge,
		  sort_for_bpf_probe_arg_vector &v);
bool sort_for_bpf(systemtap_session& s,
                  procfs_derived_probe_group *pr,
                  sort_for_bpf_probe_arg_vector &v);
bool sort_for_bpf(systemtap_session& s,
		  hrtimer_derived_probe_group *hr,
                  timer_derived_probe_group *t,
                  sort_for_bpf_probe_arg_vector &v);
bool sort_for_bpf(systemtap_session& s,
		  perf_derived_probe_group *pg,
                  sort_for_bpf_probe_arg_vector &v);
bool sort_for_bpf(systemtap_session& s,
		  tracepoint_derived_probe_group *t,
                  sort_for_bpf_probe_arg_vector &v);
bool sort_for_bpf(systemtap_session& s,
		  uprobe_derived_probe_group *u,
                  sort_for_bpf_probe_arg_vector &v);

// PR26234: Warn that a derived probe group is not supported on BPF.
// Will print "<kind> will be ignored":
void warn_for_bpf(systemtap_session& s,
                  hwbkpt_derived_probe_group *dpg,
                  const std::string& kind);
void warn_for_bpf(systemtap_session& s,
                  utrace_derived_probe_group *dpg,
                  const std::string& kind);
void warn_for_bpf(systemtap_session& s,
                  itrace_derived_probe_group *dpg,
                  const std::string& kind);
void warn_for_bpf(systemtap_session& s,
                  netfilter_derived_probe_group *dpg,
                  const std::string& kind);
void warn_for_bpf(systemtap_session& s,
                  profile_derived_probe_group *dpg,
                  const std::string& kind);
void warn_for_bpf(systemtap_session& s,
                  mark_derived_probe_group *dpg,
                  const std::string& kind);
void warn_for_bpf(systemtap_session& s,
                  python_derived_probe_group *dpg,
                  const std::string& kind);

void register_tapset_been(systemtap_session& sess);
void register_tapset_itrace(systemtap_session& sess);
void register_tapset_mark(systemtap_session& sess);
void register_tapset_procfs(systemtap_session& sess);
void register_tapset_timers(systemtap_session& sess);
void register_tapset_netfilter(systemtap_session& sess);
void register_tapset_perf(systemtap_session& sess);
void register_tapset_utrace(systemtap_session& sess);
void register_tapset_java(systemtap_session& sess);
void register_tapset_python(systemtap_session& sess);

std::string path_remove_sysroot(const systemtap_session& sess,
				const std::string& path);

// ------------------------------------------------------------------------
// Generic derived_probe_group: contains an ordinary vector of the
// given type.  It provides only the enrollment function.

template <class DP> struct generic_dpg: public derived_probe_group
{
protected:
  std::vector <DP*> probes;
public:
  generic_dpg () {}
  void enroll (DP* probe) { probes.push_back (probe); }
};


// ------------------------------------------------------------------------
// An update visitor that allows replacing assignments with a function call

struct var_expanding_visitor: public update_visitor
{
  var_expanding_visitor (systemtap_session& s);
  void visit_assignment (assignment* e);
  void visit_pre_crement (pre_crement* e);
  void visit_post_crement (post_crement* e);
  void visit_delete_statement (delete_statement* s);
  void visit_defined_op (defined_op* e);

  // PR25841: update through functions
  void visit_functioncall (functioncall* e);
  
protected:
  std::set<functiondecl*> early_resolution_in_progress;
  
  systemtap_session& sess;
  static unsigned tick;
  std::stack<defined_op*> defined_ops;
  std::set<std::string> valid_ops;
  interned_string* op;

  void provide_lvalue_call(functioncall* fcall);

private:
  std::stack<functioncall**> target_symbol_setter_functioncalls;
  bool rewrite_lvalue(const token *tok, interned_string& eop,
                      expression*& lvalue, expression*& rvalue);
};

// ------------------------------------------------------------------------

struct exp_type_dwarf : public exp_type_details
{
  // NB: We don't own this dwflpp, so don't use it after build_no_more!
  // A shared_ptr might help, but expressions are currently so leaky
  // that we'd probably never clear all references... :/
  dwflpp* dw;
  Dwarf_Die die;
  bool userspace_p;
  bool is_pointer;
  exp_type_dwarf(dwflpp* dw, Dwarf_Die* die, bool userspace_p, bool addressof);
  uintptr_t id () const { return reinterpret_cast<uintptr_t>(die.addr); }
  bool expandable() const { return true; }
  functioncall *expand(autocast_op* e, bool lvalue);
};

#endif // TAPSETS_H

/* vim: set sw=2 ts=8 cino=>4,n-2,{2,^-2,t0,(0,u0,w1,M1 : */
