/* -*- linux-c -*-
 *
 * debugfs functions
 * Copyright (C) 2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#include <linux/debugfs.h>
#include "transport.h"
#include "../uidgid_compatibility.h"




/* Always returns zero, we just push all messages on the _stp_ctl_ready_q.  */
inline static int _stp_debugfs_ctl_write_fs(int type, void *data, unsigned len)
{
	return 0;
}

static struct dentry *__stp_debugfs_root_dir = NULL;    // DEBUGFS/systemtap/
static struct dentry *__stp_debugfs_module_dir = NULL;  // DEBUGFS/systemtap/MODULE/
static struct dentry *_stp_cmd_file = NULL;             // DEBUGFS/systemtap/MODULE/.cmd


static int _stp_debugfs_register_ctl_channel_fs(void)
{
	struct dentry *module_dir = _stp_debugfs_get_module_dir();
	if (module_dir == NULL) {
		errk("no module directory found.\n");
		return -1;
	}

	/* create [debugfs]/systemtap/module_name/.cmd  */
	_stp_cmd_file = debugfs_create_file(".cmd", 0600, module_dir,
					    NULL, &_stp_ctl_fops_cmd);
	if (_stp_cmd_file == NULL) {
		errk("Error creating systemtap debugfs entries.\n");
		return -1;
	}
	else if (IS_ERR(_stp_cmd_file)) {
		_stp_cmd_file = NULL;
		errk("Error creating systemtap debugfs entries: %ld\n",
		     -PTR_ERR(_stp_cmd_file));
		return -1;
	}

	_stp_cmd_file->d_inode->i_uid = KUIDT_INIT(_stp_uid);
	_stp_cmd_file->d_inode->i_gid = KGIDT_INIT(_stp_gid);

	return 0;
}

static void _stp_debugfs_unregister_ctl_channel_fs(void)
{
	if (_stp_cmd_file)
		debugfs_remove(_stp_cmd_file);
}


static int _stp_debugfs_transport_fs_init(const char *module_name)
{
	struct dentry *root_dir;
    
	dbug_trans(1, "entry\n");
	if (module_name == NULL)
		return -1;

	if (!_stp_lock_transport_dir()) {
		errk("Couldn't lock transport directory.\n");
		return -1;
	}

	root_dir = _stp_debugfs_get_root_dir();
	if (root_dir == NULL) {
		_stp_unlock_transport_dir();
		return -1;
	}

        __stp_debugfs_module_dir = debugfs_create_dir(module_name, root_dir);
        if (!__stp_debugfs_module_dir) {
		errk("Could not create module directory \"%s\"\n",
		     module_name);
		_stp_debugfs_remove_root_dir();
		_stp_unlock_transport_dir();
		return -1;
	}
	else if (IS_ERR(__stp_debugfs_module_dir)) {
		errk("Could not create module directory \"%s\", error %ld\n",
		     module_name, -PTR_ERR(__stp_debugfs_module_dir));
		_stp_debugfs_remove_root_dir();
		_stp_unlock_transport_dir();
		return -1;
	}

	if (_stp_transport_data_fs_init() != 0) {
		debugfs_remove(__stp_debugfs_module_dir);
		__stp_debugfs_module_dir = NULL;
		_stp_debugfs_remove_root_dir();
		_stp_unlock_transport_dir();
		return -1;
	}
	_stp_unlock_transport_dir();
	dbug_trans(1, "returning 0\n");
	return 0;
}

static void _stp_debugfs_transport_fs_close(void)
{
	dbug_trans(1, "stp_transport_fs_close\n");
	_stp_transport_data_fs_close();
	if (__stp_debugfs_module_dir) {
		if (!_stp_lock_transport_dir()) {
			errk("Couldn't lock transport directory.\n");
			return;
		}

		debugfs_remove(__stp_debugfs_module_dir);
		__stp_debugfs_module_dir = NULL;

		_stp_debugfs_remove_root_dir();
		_stp_unlock_transport_dir();
	}
}


static struct dentry *_stp_lockfile = NULL;

static int _stp_lock_transport_dir(void)
{
	int numtries = 0;

	while ((_stp_lockfile = debugfs_create_dir("systemtap_lock", NULL)) == NULL) {
		if (numtries++ >= 50)
			return 0;
		msleep(50);
	}
	return 1;
}

static void _stp_unlock_transport_dir(void)
{
	if (_stp_lockfile) {
		debugfs_remove(_stp_lockfile);
		_stp_lockfile = NULL;
	}
}

/* _stp_debugfs_get_root_dir() - creates root directory or returns
 * a pointer to it if it already exists.
 *
 * The caller *must* lock the transport directory.
 */

static struct dentry *_stp_debugfs_get_root_dir(void)
{
	struct file_system_type *fs;
	struct super_block *sb;
	const char *name = "systemtap";

	if (__stp_debugfs_root_dir != NULL) {
		return __stp_debugfs_root_dir;
	}

	fs = get_fs_type("debugfs");
	if (!fs) {
		errk("Couldn't find debugfs filesystem.\n");
		return NULL;
	}

	__stp_debugfs_root_dir = debugfs_create_dir(name, NULL);
	if (__stp_debugfs_root_dir == ERR_PTR(-EEXIST)) /* some kernels signal duplication this way */
	  __stp_debugfs_root_dir = NULL;
	if (!__stp_debugfs_root_dir) {
		/* Couldn't create it because it is already there, so
		 * find it. */
#ifdef STAPCONF_FS_SUPERS_HLIST
		sb = hlist_entry(fs->fs_supers.first, struct super_block,
	 			 s_instances);
#else
		sb = list_entry(fs->fs_supers.next, struct super_block,
				s_instances);
#endif
		_stp_lock_inode(sb->s_root->d_inode);
		__stp_debugfs_root_dir = lookup_one_len(name, sb->s_root,
                                                       strlen(name));
		_stp_unlock_inode(sb->s_root->d_inode);
		if (!IS_ERR(__stp_debugfs_root_dir))
			dput(__stp_debugfs_root_dir);
		else {
			__stp_debugfs_root_dir = NULL;
			errk("Could not create or find transport directory.\n");
		}
	}
	else if (IS_ERR(__stp_debugfs_root_dir)) {
	    __stp_debugfs_root_dir = NULL;
	    errk("Could not create root directory \"%s\", error %ld\n", name,
		 -PTR_ERR(__stp_debugfs_root_dir));
	}

	return __stp_debugfs_root_dir;
}

/* _stp_debugfs_remove_root_dir() - removes root directory (if empty)
 *
 * The caller *must* lock the transport directory.
 */

static void _stp_debugfs_remove_root_dir(void)
{
	if (__stp_debugfs_root_dir) {
		if (simple_empty(__stp_debugfs_root_dir)) {
			debugfs_remove(__stp_debugfs_root_dir);
		}
		__stp_debugfs_root_dir = NULL;
	}
}

// this is used by relay_v2 to place the traceN relayfs files.
static struct dentry *_stp_debugfs_get_module_dir(void)
{
        return __stp_debugfs_module_dir;
}


// relay_v2 callbacks for creating per-cpu files

static int __stp_debugfs_relay_remove_buf_file_callback(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}


static struct dentry *
__stp_debugfs_relay_create_buf_file_callback(const char *filename,
                                            struct dentry *parent,
#ifdef STAPCONF_RELAY_UMODE_T
                                            umode_t mode,
#else
                                            int mode,
#endif
                                            struct rchan_buf *buf,
                                            int *is_global)
{
	struct dentry *file = debugfs_create_file(filename, mode, parent, buf,
	                                          &relay_file_operations_w_owner);
	/*
	 * Here's what 'is_global' does (from linux/relay.h):
	 *
	 * Setting the is_global outparam to a non-zero value will
	 * cause relay_open() to create a single global buffer rather
	 * than the default set of per-cpu buffers.
	 */
	if (is_global)
		*is_global = 0;

	if (IS_ERR(file)) {
		file = NULL;
	}
	else if (file) {
		file->d_inode->i_uid = KUIDT_INIT(_stp_uid);
		file->d_inode->i_gid = KGIDT_INIT(_stp_gid);
	}
	return file;
}

