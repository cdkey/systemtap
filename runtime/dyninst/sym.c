struct task_struct;
#include "../sym.h"
#include <assert.h>
#include <elfutils/libdwfl.h>

typedef struct
{
  char *fn;
  unsigned long offset;
} module_args;


static int
module_callback (Dwfl_Module *mod, void **userdata __attribute__((unused)),
                 const char *name, Dwarf_Addr start, void *arg)
{
  module_args *modargs = (module_args*)arg;
  if (strcmp (modargs->fn, name) == 0)
    {
      modargs->offset += start;
      return DWARF_CB_ABORT;
    }

  return DWARF_CB_OK;
}


static unsigned long _stp_umodule_relocate(const char *path,
                                           unsigned long offset,
                                           struct task_struct *task)
{
  static char *debuginfo_path;
  static const Dwfl_Callbacks proc_callbacks =
    {
      .find_debuginfo = dwfl_standard_find_debuginfo,
      .debuginfo_path = &debuginfo_path,

      .find_elf = dwfl_linux_proc_find_elf,
    };
  Dwfl *dwfl = dwfl_begin (&proc_callbacks);
  if (dwfl == NULL)
    _stp_error ("dwfl_begin: %s", dwfl_errmsg (-1));

  int result = dwfl_linux_proc_report (dwfl, getpid());
  if (result < 0)
    _stp_error ("dwfl_linux_proc_report: %s", dwfl_errmsg (-1));
  else if (result > 0)
    _stp_error ("dwfl_linux_proc_report");

  if (dwfl_report_end (dwfl, NULL, NULL) != 0)
    _stp_error ("dwfl_report_end: %s", dwfl_errmsg (-1));

   module_args modargs =
     {
       .fn = (char*)path,
       .offset = offset
     };

   if (dwfl_getmodules (dwfl, module_callback, &modargs, 0) == -1)
     _stp_error ("dwfl_getmodules: %s", dwfl_errmsg (-1));
   dwfl_end (dwfl);
   return modargs.offset;
}
