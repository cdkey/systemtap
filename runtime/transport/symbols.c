/* -*- linux-c -*-
 * symbols.c - stp symbol and module functions
 *
 * Copyright (C) Red Hat Inc, 2006-2020
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_SYMBOLS_C_
#define _STP_SYMBOLS_C_
#include "../sym.h"
#include "relay_compat.h"

#ifdef STAPCONF_KERNEL_READ_FILE_FROM_PATH_OFFSET
// XXX kernel commit b89999d004931ab2e51236 for v5.10-rc1 split
// kernel_read_file_* functions into a separate header.
#include <linux/kernel_read_file.h>
#endif

#ifndef KERN_CONT
#define KERN_CONT	""
#endif

static int _stp_kmodule_check (const char*);

/* PR12612: pre-commit-3abb860f values */

#define STP13_MODULE_NAME_LEN 64
#define STP13_SYMBOL_NAME_LEN 64
struct _stp13_msg_relocation {
        char module[STP13_MODULE_NAME_LEN];
        char reloc[STP13_SYMBOL_NAME_LEN];
        uint64_t address;
};

static void _stp_set_stext(uint64_t address)
{
        if (address == 0)
                _stp_warn("No load address found _stext.  Kernel probes and addresses may not be available.");
        else
                dbug_sym(1, "found kernel _stext load address: 0x%lx\n",
                         (unsigned long) address);
        if (_stp_kretprobe_trampoline != (unsigned long) -1)
                _stp_kretprobe_trampoline += (unsigned long) address;
}

static void _stp_do_relocation(const char __user *buf, size_t count)
{
  static struct _stp_msg_relocation msg; /* by protocol, never concurrently used */
  static struct _stp13_msg_relocation msg13; /* ditto */

  /* PR12612: Let's try to be compatible with systemtap modules being
     compiled by new systemtap, but loaded (staprun'd) by an older
     systemtap runtime.  The only known incompatilibility is that we
     get an older, smaller, relocation message.  So here we accept both
     sizes. */
  if (sizeof(msg) == count) { /* systemtap 1.4+ runtime */
    if (unlikely(copy_from_user (& msg, buf, count)))
            return;
  } else if (sizeof(msg13) == count) { /* systemtap 1.3- runtime */
    if (unlikely(copy_from_user (& msg13, buf, count)))
            return;
#if STP_MODULE_NAME_LEN <= STP13_MODULE_NAME_LEN
#error "STP_MODULE_NAME_LEN should not be smaller than STP13_MODULE_NAME_LEN"
#endif
    strlcpy (msg.module, msg13.module, STP13_MODULE_NAME_LEN);
    strlcpy (msg.reloc, msg13.reloc, STP13_MODULE_NAME_LEN);
    msg.address = msg13.address;
  } else {
      errk ("STP_RELOCATE message size mismatch (%lu or %lu vs %lu)\n",
            (long unsigned) sizeof(msg), (long unsigned) sizeof (msg13), (long unsigned) count);
      return;
  }

  dbug_sym(2, "relocate (%s %s 0x%lx)\n", msg.module, msg.reloc, (unsigned long) msg.address);

  /* Detect actual kernel load address. */
  if (!strcmp ("kernel", msg.module)
      && !strcmp ("_stext", msg.reloc)) {
#ifdef CONFIG_KALLSYMS
          // PR14555, PR26074: kptr_restrict=2 may hide _stext from
          // staprun. We fall back by calling kallsyms_lookup_name,
          // but this may need to be done later once
          // kallsyms_lookup_name has been passed via relocation:
#if !defined(STAPCONF_KALLSYMS_LOOKUP_NAME_EXPORTED)
          if (msg.address == 0)
                  _stp_need_kallsyms_stext = 1;
          else
                  _stp_set_stext(msg.address);
#else
          if (msg.address == 0)
                  msg.address = kallsyms_lookup_name("_stext");
          _stp_set_stext(msg.address);
#endif
#else
          _stp_set_stext(msg.address);
#endif
  }

#if !defined(STAPCONF_KALLSYMS_LOOKUP_NAME_EXPORTED)
  if (!strcmp ("kernel", msg.module)
      && !strcmp ("kallsyms_lookup_name", msg.reloc)) {
          _stp_kallsyms_lookup_name = (void *) msg.address;
  }
#endif
#if defined(STAPCONF_KALLSYMS_ON_EACH_SYMBOL) && !defined(STAPCONF_KALLSYMS_ON_EACH_SYMBOL_EXPORTED)
  if (!strcmp ("kernel", msg.module)
      && !strcmp ("kallsyms_on_each_symbol", msg.reloc)) {
          _stp_kallsyms_on_each_symbol = (void *) msg.address;
  }
#endif

  _stp_kmodule_update_address(msg.module, msg.reloc, msg.address);
}



/* Module section attributes tell us where module sections are/were
   loaded intoi kernel memory.  In the kernel APIs, these have gone
   through enough change over the years, that we roll our own now.
 */
struct stap_module_sect_attr
{
        const char* name;
        unsigned long address;
};

struct stap_module_sect_attrs
{
        unsigned nsections;
        struct stap_module_sect_attr *sections;
};


// Allocates & fills in as->nsections and as->attrs[].  Addresses may be 0L
// if addresses unknown or invalid.  Free with put_() function below.  Do not
// keep alive any longer than target module's notifier callback, as section
// names (in attrs[]) are considered static.  In case of error, mod->nsections
// may be zero and/or mod->sections[i].address may be zero.
void get_module_sect_attrs(struct module* mod,
                           struct stap_module_sect_attrs* as);

void put_module_sect_attrs(struct stap_module_sect_attrs* as)
{
        _stp_kfree(as->sections);
}

static ssize_t _stp_read_file_from_path(const char *path, char *buf, size_t len)
{
	struct file *file;
	loff_t pos = 0;
	ssize_t ret;

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);

#ifdef STAPCONF_KERNEL_READ_NEW_ARGS
	ret = kernel_read(file, buf, len, &pos);
#else
	ret = kernel_read(file, pos, buf, len);
#endif
	fput(file);
	return ret;
}

static unsigned long
read_sect_sysfs(const char* module, const char *section)
{
        char *pathname = __getname(); // PATH_MAX sized
        int rc;
        unsigned long addr = 0;
	char buffer[32] = {}; // Sections files are 19 bytes in size at most

        if (pathname == 0)
                goto out;
        rc = snprintf(pathname, PATH_MAX, "/sys/module/%s/sections/%s", module, section);
        if (rc >= PATH_MAX)
                goto out1;
	rc = _stp_read_file_from_path(pathname, buffer, sizeof(buffer));
	if (rc <= 0)
		goto out1;
        rc = kstrtoul(buffer, 0, &addr);
        if (rc != 0) // parse error?
                addr = 0L;
out1:
        __putname(pathname);
out:
        dbug_sym(2, "module %s section %s address 0x%lu\n",
                 module, section, addr);
        
        return addr;
}
                                     

void get_module_sect_attrs(struct module* mod,
                           struct stap_module_sect_attrs* as)
{
        unsigned i;
        
        // Guess at the maximal set of sections we're likely to encounter
        // as relevant for probing, $context var setting, unwinding; more welcome.
        // It's not easy to say "all" because we can't enumerate them
        const char* key_sections[] = { ".init", ".text", ".eh_frame",
                                       ".text.unlikely", ".data", ".rodata",
                                       ".symtab" };
        as->nsections = sizeof(key_sections)/sizeof(key_sections[0]);
        as->sections = _stp_kzalloc(as->nsections * sizeof(struct stap_module_sect_attr));
        if (as->sections == 0) {
                goto out1;
        }

        for (i=0; i<as->nsections; i++) {
                as->sections[i].name = key_sections[i];
                as->sections[i].address = read_sect_sysfs(mod->name, key_sections[i]);
        }
        
        goto out;

out1:
        as->nsections = 0; // prevent later kfrees run amok
out:
        return;
}

static int _stp_module_notifier (struct notifier_block * nb,
                                 unsigned long val, void *data)
{
        struct module *mod = data;
        if (!mod) { // so as to avoid null pointer checks later
                WARN_ON (!mod);
                return NOTIFY_DONE;
        }

        dbug_sym(1, "module notify %lu %s\n",
                 val, mod->name);

        /* Prior to 2.6.11, struct module contained a module_sections
           attribute vector rather than module_sect_attrs.  Prior to
           2.6.19, module_sect_attrs lacked a number-of-sections
           field.  Past 3.8, MODULE_STATE_COMING is sent too late to
           let us probe module init functions.

           Without CONFIG_KALLSYMS, we don't get any of the
           related fields at all in struct module.  XXX: autoconf for
           that directly? */

#if defined(CONFIG_KALLSYMS)
	// After kernel commit 4982223e51, module notifiers are being
	// called too early to get module section info. So, we have to
	// switch to using symbol+offset probing for modules.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	// The module refresh code (in systemtap_module_refresh)
	// assumes the 1st call is on module load and the 2nd is on
	// module unload. So, we can't call systemtap_module_refresh()
	// twice for module load (once for MODULE_STATE_COMING and
	// once for MODULE_STATE_LIVE). In the MODULE_STATE_COMING
	// state, the module's init function hasn't fired yet and we
	// can register symbol+offset probes. In the MODULE_STATE_LIVE
	// state, the module's init function has already been run (and
	// the init section has been discarded). So, we'll ignore
	// MODULE_STATE_LIVE.
        if (val == MODULE_STATE_COMING) {
		/* Verify build-id. */
		_stp_kmodule_check (mod->name);
        }
        else if (val == MODULE_STATE_GOING) {
		/* Unregister all sections. */
		dbug_sym(2, "unregister sections\n");
		_stp_kmodule_update_address(mod->name, NULL, 0);
        }
        else if (val != MODULE_STATE_GOING) {
		return NOTIFY_DONE;
        }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
        if (val == MODULE_STATE_COMING ||
            val == MODULE_STATE_LIVE) {
                /* A module is arriving or has arrived.  Register all
                   of its section addresses, as though staprun sent us
                   a bunch of STP_RELOCATE messages.  Now ... where
                   did the fishie go? */
                
                struct stap_module_sect_attrs attrs;
                unsigned i, nsections;
                get_module_sect_attrs (mod, &attrs);

                for (i=0; i<attrs.nsections; i++) {
                        int init_p = (strstr(attrs.sections[i].name, "init.") != NULL);
                        int init_gone_p = (val == MODULE_STATE_LIVE); // likely already unloaded

                        _stp_kmodule_update_address(mod->name,
                                                    attrs.sections[i].name,
                                                    ((init_p && init_gone_p) ? 0 : attrs.sections[i].address));
                }

                put_module_sect_attrs (&attrs);

                /* Verify build-id. */
                if (_stp_kmodule_check (mod->name))
                   _stp_kmodule_update_address(mod->name, NULL, 0); /* Pretend it was never here. */
        }
        else if (val == MODULE_STATE_GOING) {
                /* Unregister all sections. */
                _stp_kmodule_update_address(mod->name, NULL, 0);
        }
	else
		return NOTIFY_DONE;
#endif

        /* Give the probes a chance to update themselves. */
        /* Proper kprobes support for this appears to be relatively
           recent.  Example prerequisite commits: 0deddf436a f24659d9 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        systemtap_module_refresh(mod->name);
#endif

#endif /* skipped for ancient or kallsyms-free kernels */

        return NOTIFY_DONE;
}

static int _stp_module_update_self (void)
{
	/* Only bother if we need unwinding and have module_sect_attrs.  */
  /* Or if we need to figure out the addr->file:line mapping */
#if (defined(STP_USE_DWARF_UNWINDER) && defined(STP_NEED_UNWIND_DATA)) \
    || defined(STP_NEED_LINE_DATA)
#if defined(CONFIG_KALLSYMS)  && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)

	bool found_eh_frame = false;
	struct module *mod = THIS_MODULE;
        struct stap_module_sect_attrs attrs;
        int rc;
        unsigned i;
        
	/* We've already been inserted at this point, so the path variable will
	 * still be unique.  */
	_stp_module_self.name = mod->name;
	_stp_module_self.path = mod->name;

        get_module_sect_attrs (mod, &attrs);

	for (i=0; i<attrs.nsections; i++) {
                const char* aname = attrs.sections[i].name;
                unsigned long address = attrs.sections[i].address;
                
                if (! aname)
                        continue;
		if(!strcmp(".note.gnu.build-id",aname)) {
			_stp_module_self.notes_sect = address;
		}
		else if (!strcmp(".eh_frame", aname)) {
			_stp_module_self.eh_frame = (void*)address;
			_stp_module_self.eh_frame_len = 0;
			found_eh_frame = true;
		}
		else if (!strcmp(".symtab", aname)) {
#ifdef STAPCONF_MOD_KALLSYMS
			struct mod_kallsyms *kallsyms;

			rcu_read_lock_sched();
			kallsyms = rcu_dereference_sched(mod->kallsyms);
			rcu_read_unlock_sched();

			if (address == (unsigned long) kallsyms->symtab)
				_stp_module_self.sections[0].size =
					kallsyms->num_symtab * sizeof(kallsyms->symtab[0]);
#else
			if (address == (unsigned long) mod->symtab)
				_stp_module_self.sections[0].size =
					mod->num_symtab * sizeof(mod->symtab[0]);
#endif
			_stp_module_self.sections[0].static_addr = address;
		}
		else if (!strcmp(".text", aname)) {
			_stp_module_self.sections[1].static_addr = address;
#ifdef STAPCONF_MODULE_LAYOUT
			_stp_module_self.sections[1].size = mod->core_layout.text_size;
#elif defined(STAPCONF_GRSECURITY)
                        _stp_module_self.sections[1].size = mod->core_size_rx;
#else
			_stp_module_self.sections[1].size = mod->core_text_size;
#endif
		}
	}

	if (found_eh_frame) {
		/* Scan again for an upper bound on eh_frame_len, deduced from
		 * the position of the next closest section.  (if any!)  */
		const unsigned long base = (unsigned long) _stp_module_self.eh_frame;
		unsigned long maxlen = 0, len = 0;
		for (i=0; i<attrs.nsections; i++) {
			unsigned long address = attrs.sections[i].address;
			if (base < address && (maxlen == 0 || address < base + maxlen))
				maxlen = address - base;
		}

		/* The length could be smaller, especially if the next section
		 * has alignment padding.  Walking the fde determines the real
		 * eh_frame length.  There should be a 0x00000000 terminator
		 * word added by translate.cxx's T_800 auxiliary file, but
		 * check our maxlen bound just in case.  */
		while (len + sizeof(u32) <= maxlen) {
			unsigned long offset = get_unaligned((u32*)(base + len));
			if (offset == 0 || offset > maxlen - len - sizeof(u32))
				break; /* 0-terminator, or out of bounds */
			len += sizeof(u32) + offset;
		}
		_stp_module_self.eh_frame_len = len;
	}

        put_module_sect_attrs (&attrs);
        
#endif /* defined(CONFIG_KALLSYMS) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11) */
#endif /* (defined(STP_USE_DWARF_UNWINDER) && defined(STP_NEED_UNWIND_DATA))
          || defined(STP_NEED_LINE_DATA) */

	return 0;
}

/* Notification function to call on a kernel panic */
static int _stp_module_panic_notifier (struct notifier_block *nb, unsigned long val, void *data)
{
        int i;

	if (unlikely(_stp_relay_data.rchan == NULL))
	{
		printk(KERN_ERR "No _stp_relay_data.rchan\n");
		return NOTIFY_DONE;
	}

        /* Loop over each cpu buffer */
        for_each_possible_cpu(i)
        {
                int j=0;
                struct rchan_buf * sub_buf;
                char *subbuf_start;
                char *previous;
                char *next;
                size_t bytes_passed;
                int printed;
                int first_iteration;

                sub_buf = _stp_get_rchan_subbuf(_stp_relay_data.rchan->buf, i);
		if (unlikely(sub_buf == NULL))
			break;

                /* Set our pointer to the beginning of the channel buffer */
                subbuf_start = (char *)sub_buf->start;

                /* Loop over each sub buffer */
                for (j=0; j< sub_buf->chan->n_subbufs; j++)
                {
                        /* Ensure our start is not NULL */
                        if(subbuf_start == NULL)
                        {
                                printk(KERN_EMERG "Current buffer is NULL\n");
                                return NOTIFY_DONE;
                        }

                        bytes_passed = 0; /* Keep track of the number of bytes already passed */
                        first_iteration = 1; /* Flag for keeping track of the 1st itteration*/
                        printed = 0; /* Flag for keeping track of when we've already printed the
                                      * message about what info might be new */

                        previous = subbuf_start;
                        next = strchr(previous, '\n');
                        bytes_passed+= (next - previous);

                        /* Loop over the whole buffer, printing line by line */
                        while (next != NULL && bytes_passed < sub_buf->chan->subbuf_size)
                        {

                                if(first_iteration)
                                {
                                        printk(KERN_CONT "%s trace buffer for processor %d sub-buffer %d:\n",
                                               THIS_MODULE->name, i, j);
                                }

                                /* Once we reach the number of bytes consumed on the last
                                 * sub-buffer filled, print a message saying that everything
                                 * from then on might not have made it to the display before
                                 * the kernel panic */
                                if(subbuf_start == sub_buf->data
                                   && bytes_passed >= sub_buf->bytes_consumed
                                   && !printed)
                                {
                                        printk(KERN_CONT
                                               "The following may not have been sent to the display:\n");
                                        printed = 1;
                                }

                                /* Print the line. Other than the first itteration, we need to print everything
                                 * except the first '\n' character.*/
                                if(first_iteration)
                                {
                                        printk(KERN_CONT "%.*s\n", (int)(next - previous), previous);
                                        first_iteration = 0;
                                }
                                else
                                {
                                        printk(KERN_CONT "%.*s\n", (int)(next - previous)-1, previous+1);
                                }

                                /* Get the next token */
                                previous = next;
                                next = strchr(next + 1, '\n');
                                if(next != NULL)
                                {
                                        bytes_passed+= (next - previous);
                                }
                        }

                        /* Move on to the next sub-buffer */
                        subbuf_start = subbuf_start + sub_buf->chan->subbuf_size;
                }
        }
        return NOTIFY_DONE;
}

#endif /* _STP_SYMBOLS_C_ */
