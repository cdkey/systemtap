/* -*- linux-c -*-
 *
 * /proc command channels
 * Copyright (C) 2007-2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_PROCFS_C_
#define _STP_PROCFS_C_

#if (!defined(STAPCONF_PATH_LOOKUP) && !defined(STAPCONF_KERN_PATH_PARENT) \
     && !defined(STAPCONF_VFS_PATH_LOOKUP) && !defined(STAPCONF_KERN_PATH))
#error "Either path_lookup(), kern_path_parent(), vfs_path_lookup(), or kern_path() must be exported by the kernel."
#endif

#ifdef STAPCONF_KERN_PATH
#include <linux/namei.h>
#endif
#ifdef STAPCONF_VFS_PATH_LOOKUP
#include <linux/mount.h>
#include <linux/pid_namespace.h>
#endif
#include "proc_fs_compatibility.h"
#include "uidgid_compatibility.h"


/* If STAPCONF_PDE_DATA isn't defined, we're using the original /proc
 * interface (where 'struct proc_dir_entry' isn't opaque). In this
 * case allow the (undocumented) feature of slashes
 * (i.e. subdirectories) in paths. */
#ifndef STAPCONF_PDE_DATA
#define _STP_ALLOW_PROCFS_PATH_SUBDIRS
#endif

/* The maximum number of files that can be opened.  Plus if
 * _STP_ALLOW_PROCFS_PATH_SUBDIRS, add number of directories.
 */
#ifndef STP_MAX_PROCFS_FILES
#error "need STP_MAX_PROCFS_FILES"
#endif

static int _stp_num_pde = 0;
static struct proc_dir_entry *_stp_pde[STP_MAX_PROCFS_FILES];

static void _stp_close_procfs(void);




#ifdef _STP_ALLOW_PROCFS_PATH_SUBDIRS
/*
 * This checks our local cache to see if we already made the dir.
 */
static struct proc_dir_entry *_stp_procfs_lookup(const char *dir, struct proc_dir_entry *parent)
{
	int i;
	for (i = 0; i <_stp_num_pde; i++) {
		struct proc_dir_entry *pde = _stp_pde[i];
		if (pde->parent == parent && !strcmp(dir, pde->name))
			return pde;
	}
	return NULL;
}
#endif	/* _STP_ALLOW_PROCFS_PATH_SUBDIRS */


static int _stp_create_procfs(const char *path,
#ifdef STAPCONF_PROC_OPS
                              const struct proc_ops *fops,
#else
                              const struct file_operations *fops,
#endif
                              int perm, void *data)
{
	const char *p; char *next;
	struct proc_dir_entry *last_dir, *de;

	if (_stp_num_pde >= STP_MAX_PROCFS_FILES)
		goto too_many;

	last_dir = _stp_procfs_module_dir;

	/* if no path, use default one */
	if (strlen(path) == 0)
		p = "command";
	else
		p = path;
	
#ifdef _STP_ALLOW_PROCFS_PATH_SUBDIRS
	while ((next = strchr(p, '/'))) {
		if (_stp_num_pde == STP_MAX_PROCFS_FILES)
			goto too_many;
		*next = 0;
		de = _stp_procfs_lookup(p, last_dir);
		if (de == NULL) {
			last_dir = proc_mkdir(p, last_dir);
			if (!last_dir) {
				_stp_error("Could not create directory \"%s\"\n", p);
				goto err;
			}
			_stp_pde[_stp_num_pde++] = last_dir;
#ifdef STAPCONF_PROCFS_OWNER
			last_dir->owner = THIS_MODULE;
#endif
			proc_set_user(last_dir, KUIDT_INIT(_stp_uid),
				      KGIDT_INIT(_stp_gid));
		}
		else {
			last_dir = de;
		}
		p = next + 1;
	}
#else  /* !_STP_ALLOW_PROCFS_PATH_SUBDIRS */
	if (strchr(p, '/') != NULL) {
		_stp_error("Could not create path \"%s\","
			   " contains subdirectories\n", p);
		goto err;
	}
#endif	/* !_STP_ALLOW_PROCFS_PATH_SUBDIRS */
	
	if (_stp_num_pde == STP_MAX_PROCFS_FILES)
		goto too_many;
	
	de = proc_create_data(p, perm, last_dir, fops, data);
	if (de == NULL)
                return 0; // already created
#ifdef STAPCONF_PROCFS_OWNER
	de->owner = THIS_MODULE;
#endif
	proc_set_user(de, KUIDT_INIT(_stp_uid), KGIDT_INIT(_stp_gid));
	_stp_pde[_stp_num_pde++] = de;
	return 0;
	
too_many:
	_stp_error("Attempted to open too many procfs files. Maximum is %d\n",
		   STP_MAX_PROCFS_FILES);
err:
	_stp_close_procfs();
	return -1;
}

static void _stp_close_procfs(void)
{
	int i;
	for (i = _stp_num_pde-1; i >= 0; i--) {
		struct proc_dir_entry *pde = _stp_pde[i];
		proc_remove(pde);
	}
	_stp_num_pde = 0;
}

#endif	/* _STP_PROCFS_C_ */
