/* -*- linux-c -*-
 *
 * /proc transport and control
 * Copyright (C) 2005-2018 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#include "relay_compat.h"


/* _stp_procfs_module_dir is the '/proc/systemtap/{module_name}' directory. */
static struct proc_dir_entry *_stp_procfs_module_dir = NULL;
static struct path _stp_procfs_module_dir_path;

/*
 * Safely creates '/proc/systemtap' (if necessary) and
 * '/proc/systemtap/{module_name}'.
 *
 * NB: this function is suitable to call from early in the the
 * module-init function, and doesn't rely on any other facilities
 * in our runtime.  PR19833.  See also PR15408.
 */
static int _stp_mkdir_proc_module(void)
{	
	int found = 0;
	static char proc_root_name[STP_MODULE_NAME_LEN + sizeof("systemtap/")];
#if defined(STAPCONF_PATH_LOOKUP) || defined(STAPCONF_KERN_PATH_PARENT)
	struct nameidata nd;
#else  /* STAPCONF_VFS_PATH_LOOKUP or STAPCONF_KERN_PATH */
	struct path path;
#if defined(STAPCONF_VFS_PATH_LOOKUP)
	struct vfsmount *mnt;
#endif
	int rc;
#endif	/* STAPCONF_VFS_PATH_LOOKUP or STAPCONF_KERN_PATH */

        if (_stp_procfs_module_dir != NULL)
		return 0;

#if defined(STAPCONF_PATH_LOOKUP) || defined(STAPCONF_KERN_PATH_PARENT)
	/* Why "/proc/systemtap/foo"?  kern_path_parent() is basically
	 * the same thing as calling the old path_lookup() with flags
	 * set to LOOKUP_PARENT, which means to look up the parent of
	 * the path, which in this case is "/proc/systemtap". */
	if (! kern_path_parent("/proc/systemtap/foo", &nd)) {
		found = 1;
#ifdef STAPCONF_NAMEIDATA_CLEANUP
		path_put(&nd.path);
#else  /* !STAPCONF_NAMEIDATA_CLEANUP */
		path_release(&nd);
#endif	/* !STAPCONF_NAMEIDATA_CLEANUP */
	}

#elif defined(STAPCONF_KERN_PATH)
	/* Prefer kern_path() over vfs_path_lookup(), since on some
	 * kernels the declaration for vfs_path_lookup() was moved to
	 * a private header. */

	/* See if '/proc/systemtap' exists. */
	rc = kern_path("/proc/systemtap", 0, &path);
	if (rc == 0) {
		found = 1;
		path_put (&path);
	}

#else  /* STAPCONF_VFS_PATH_LOOKUP */
	/* See if '/proc/systemtap' exists. */
	if (! init_pid_ns.proc_mnt) {
		errk("Unable to create '/proc/systemap':"
		     " '/proc' doesn't exist.\n");
		goto done;
	}
	mnt = init_pid_ns.proc_mnt;
	rc = vfs_path_lookup(mnt->mnt_root, mnt, "systemtap", 0, &path);
	if (rc == 0) {
		found = 1;
		path_put (&path);
	}
#endif	/* STAPCONF_VFS_PATH_LOOKUP */

	/* If we couldn't find "/proc/systemtap", create it. */
	if (!found) {
		struct proc_dir_entry *de;

		de = proc_mkdir ("systemtap", NULL);
		if (de == NULL) {
			errk("Unable to create '/proc/systemap':"
			     " proc_mkdir failed.\n");
			goto done;
 		}
	}

	/* Create the "systemtap/{module_name} directory in procfs. */
	strlcpy(proc_root_name, "/proc/systemtap/", sizeof(proc_root_name));
	strlcat(proc_root_name, THIS_MODULE->name, sizeof(proc_root_name));
	_stp_procfs_module_dir = proc_mkdir(&proc_root_name[6], NULL); // skip the /proc/
#ifdef STAPCONF_PROCFS_OWNER
	if (_stp_procfs_module_dir != NULL)
		_stp_procfs_module_dir->owner = THIS_MODULE;
#endif
	if (_stp_procfs_module_dir == NULL)
		errk("Unable to create '/proc/systemap/%s':"
		     " proc_mkdir failed.\n", THIS_MODULE->name);
        else {
                rc = kern_path(proc_root_name, 0, &_stp_procfs_module_dir_path);
                if (rc != 0) {
                        errk("Unable to resolve /proc/systemap/%s':"
                             " to path.\n", THIS_MODULE->name);
                        proc_remove(_stp_procfs_module_dir);
                        _stp_procfs_module_dir = NULL;
                        return rc;
                }
        }

done:
	return (_stp_procfs_module_dir) ? 0 : -EINVAL;
}


/*
 * Removes '/proc/systemtap/{module_name}'. Notice we're leaving
 * '/proc/systemtap' behind.  There is no way on newer kernels to know
 * if a procfs directory is empty.
 *
 * NB: this is suitable to call late in the module cleanup function,
 * and does not rely on any other facilities in the runtime.  PR19833.
 * See also PR15408.
 */
static void _stp_rmdir_proc_module(void)
{
	if (_stp_procfs_module_dir) {
                path_put(& _stp_procfs_module_dir_path);
		proc_remove(_stp_procfs_module_dir);
		_stp_procfs_module_dir = NULL;
	}
}


inline static int _stp_procfs_ctl_write_fs(int type, void *data, unsigned len)
{
	struct _stp_buffer *bptr;
	unsigned long flags;

#define WRITE_AGG
#ifdef WRITE_AGG
	stp_spin_lock_irqsave(&_stp_ctl_ready_lock, flags);
	if (!list_empty(&_stp_ctl_ready_q)) {
		bptr = (struct _stp_buffer *)_stp_ctl_ready_q.prev;
		if ((bptr->len + len) <= STP_CTL_BUFFER_SIZE
		    && type == STP_REALTIME_DATA
		    && bptr->type == STP_REALTIME_DATA) {
			memcpy(bptr->buf + bptr->len, data, len);
			bptr->len += len;
			stp_spin_unlock_irqrestore(&_stp_ctl_ready_lock, flags);
			return len;
		}
	}
	stp_spin_unlock_irqrestore(&_stp_ctl_ready_lock, flags);
#endif
	return 0;
}

static int _stp_proc_ctl_read_bufsize(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len = sprintf(page, "%d,%d\n", _stp_nsubbufs, _stp_subbuf_size);
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;
}


static struct file_operations _stp_ctl_fops_cmd;
#ifdef STAPCONF_PROC_OPS /* control.c */
static struct proc_ops _stp_ctl_proc_ops_cmd;
#endif


static int _stp_procfs_register_ctl_channel_fs(void)
{
	struct proc_dir_entry *bs = NULL;
	struct proc_dir_entry *de;

	if (_stp_mkdir_proc_module())
		goto err0;

	/* create /proc/systemtap/module_name/.cmd  */
#ifdef STAPCONF_PROC_OPS
	de = proc_create(".cmd", 0600, _stp_procfs_module_dir, &_stp_ctl_proc_ops_cmd);
#else
	de = proc_create(".cmd", 0600, _stp_procfs_module_dir, &_stp_ctl_fops_cmd);        
#endif
	if (de == NULL)
		goto err1;
        proc_set_user(de, KUIDT_INIT(_stp_uid), KGIDT_INIT(_stp_gid));

	return 0;

err1:
	_stp_rmdir_proc_module();
err0:
	return -1;
}

static void _stp_procfs_unregister_ctl_channel_fs(void)
{
	remove_proc_entry(".cmd", _stp_procfs_module_dir);
	_stp_rmdir_proc_module();
}



#ifdef STAPCONF_PROC_OPS
struct proc_ops relay_procfs_operations;
#else
struct file_operations relay_procfs_operations;
#endif


static int _stp_procfs_transport_fs_init(const char *module_name)
{
#ifdef STAPCONF_PROC_OPS
  relay_procfs_operations.proc_open = relay_file_operations.open;
  relay_procfs_operations.proc_poll = relay_file_operations.poll;
  relay_procfs_operations.proc_mmap = relay_file_operations.mmap;
  relay_procfs_operations.proc_read = relay_file_operations.read;
  relay_procfs_operations.proc_lseek = relay_file_operations.llseek;
  relay_procfs_operations.proc_release = relay_file_operations.release;
#else
  relay_procfs_operations = relay_file_operations;
  relay_procfs_operations.owner = THIS_MODULE;
#endif
  
  if (_stp_mkdir_proc_module()) // get the _stp_procfs_module_dir* created
          return -1;

  dbug_trans(1, "transport_fs_init dentry=%08lx pde=%08lx ",
             (unsigned long) _stp_procfs_module_dir_path.dentry,
             (unsigned long) _stp_procfs_module_dir);
  
  if (_stp_transport_data_fs_init() != 0)
          return -1;
  
  return 0;
}


static void _stp_procfs_transport_fs_close(void)
{
	_stp_transport_data_fs_close();
}



// We need to map procfs concepts of proc_dir_entry* and relayfs/vfs of path/dentry*.
#define MAX_RELAYFS_FILES NR_CPUS
struct procfs_relay_file
{
        struct path p;               // contains the dentry*
        struct proc_dir_entry *pde;  // entry valid if this pointer non-NULL
};
struct procfs_relay_file p_r_files[MAX_RELAYFS_FILES];



static struct dentry *_stp_procfs_get_module_dir(void)
{
        return _stp_procfs_module_dir_path.dentry;
}


static int __stp_procfs_relay_remove_buf_file_callback(struct dentry *dentry)
{
  unsigned i;
  struct proc_dir_entry *pde = NULL;
  
  // find the corresponding pde*
  for (i=0; i<MAX_RELAYFS_FILES; i++)
    {
      if (p_r_files[i].pde != NULL &&
          p_r_files[i].p.dentry == dentry)
        break;
    }

  if (i != MAX_RELAYFS_FILES)
    {
      pde = p_r_files[i].pde;
      path_put (& p_r_files[i].p);
      proc_remove (pde);
      p_r_files[i].pde = NULL;
    }
  
  dbug_trans(1, "remove-buf dentry=%08lx pde=%08lx i=%u",
             (unsigned long) dentry, (unsigned long) pde, i);
  return 0;
}


static struct dentry *
__stp_procfs_relay_create_buf_file_callback(const char *filename,
                                            struct dentry *parent,
#ifdef STAPCONF_RELAY_UMODE_T
                                            umode_t mode,
#else
                                            int mode,
#endif
                                            struct rchan_buf *buf,
                                            int *is_global)
{
  int rc = 0;
  struct dentry* de = NULL;
  char fullpath[sizeof("/proc/systemtap") + STP_MODULE_NAME_LEN + sizeof("/traceNNNNN") + 42];
  struct proc_dir_entry *pde;
  unsigned i = 0;
  struct inode* in;
  
  if (is_global) {
#ifdef STP_BULKMODE
          *is_global = 0;
#else
          *is_global = 1;
#endif
  }
  
  if (parent != _stp_procfs_module_dir_path.dentry)
    goto out;
  
  pde = proc_create (filename, 0600,
                     _stp_procfs_module_dir,
                     & relay_procfs_operations);
  if (pde == NULL)
    goto out;

  rc = snprintf(fullpath, sizeof(fullpath), "/proc/systemtap/%s/%s",
                THIS_MODULE->name, filename);
  
  // find spot to plop this
  for (i=0; i<MAX_RELAYFS_FILES; i++)
    {
      if (p_r_files[i].pde == NULL)
        break;
    }
  if (i == MAX_RELAYFS_FILES)
    goto out1;
  
  rc = kern_path (fullpath, 0, &p_r_files[i].p);
  if (rc)
    goto out1;
  p_r_files[i].pde = pde;
  de = p_r_files[i].p.dentry;
  
  // fill in the relayfs i_private
  in = de->d_inode;
  in->i_private = buf;
  
  // success!
  goto out;
  
out1:
  proc_remove (pde);

out:
  dbug_trans(1, "create-buf name=%s parent=%08lx -> i=%u rc=%d de=%08lx",
             filename, (unsigned long) parent,
             i, rc, (unsigned long) de);
  return de;
}
