/* -*- linux-c -*- 
 *
 * This transport version uses relayfs on top of a debugfs or procfs
 * file.  This code started as a proposed relayfs interface called
 * 'utt'.  It has been modified and simplified for systemtap.
 *
 * Changes Copyright (C) 2009-2020 Red Hat Inc.
 *
 * Original utt code by:
 *   Copyright (C) 2006 Jens Axboe <axboe@suse.de>
 *   Moved to utt.c by Tom Zanussi, 2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/mm.h>
#include "../linux/timer_compatibility.h"
#include "../uidgid_compatibility.h"
#include "relay_compat.h"

#ifndef STP_RELAY_TIMER_INTERVAL
/* Wakeup timer interval in jiffies (default 10 ms) */
#define STP_RELAY_TIMER_INTERVAL		((HZ + 99) / 100)
#endif

/* Note: if struct _stp_relay_data_type changes, staplog.c might need
 * to be changed. */
struct _stp_relay_data_type {
	struct rchan *rchan;
	atomic_t /* enum _stp_transport_state */ transport_state;
	atomic_t wakeup;
	struct timer_list timer;
	int overwrite_flag;
};
struct _stp_relay_data_type _stp_relay_data;

/* relay_file_operations is const, so .owner is obviously not set there.
 * Below struct, filled in _stp_transport_data_fs_init(), fixes it. */
static struct file_operations relay_file_operations_w_owner;

/*
 *	__stp_relay_switch_subbuf - switch to a new sub-buffer
 *
 *	Most of this function is deadcopy of relay_switch_subbuf.
 */
static size_t __stp_relay_switch_subbuf(struct rchan_buf *buf, size_t length)
{
	char *old, *new;
	size_t old_subbuf, new_subbuf;

	if (unlikely(buf == NULL))
		return 0;

	if (unlikely(length > buf->chan->subbuf_size))
		length = buf->chan->subbuf_size;

	if (buf->offset != buf->chan->subbuf_size + 1) {
		buf->prev_padding = buf->chan->subbuf_size - buf->offset;
		old_subbuf = buf->subbufs_produced % buf->chan->n_subbufs;
		buf->padding[old_subbuf] = buf->prev_padding;
		buf->subbufs_produced++;
		buf->dentry->d_inode->i_size += buf->chan->subbuf_size -
			buf->padding[old_subbuf];
		smp_mb();
	}

	old = buf->data;
	new_subbuf = buf->subbufs_produced % buf->chan->n_subbufs;
	new = (char*)buf->start + new_subbuf * buf->chan->subbuf_size;
	buf->offset = 0;
	if (!buf->chan->cb->subbuf_start(buf, new, old, buf->prev_padding)) {
		buf->offset = buf->chan->subbuf_size + 1;
		return 0;
	}
	buf->data = new;
	buf->padding[new_subbuf] = 0;

	return length;
}

static bool __stp_relay_buf_empty(struct rchan_buf *buf)
{
	return !buf->offset && buf->subbufs_produced == buf->subbufs_consumed;
}

static unsigned int __stp_relay_file_poll(struct file *filp, poll_table *wait)
{
	struct rchan_buf *buf = filp->private_data;

	if (buf->finalized)
		return POLLERR;

	if (filp->f_mode & FMODE_READ) {
		poll_wait(filp, &buf->read_wait, wait);
		if (!__stp_relay_buf_empty(buf))
			return POLLIN | POLLRDNORM;
	}

	return 0;
}

static ssize_t __stp_relay_file_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct rchan_buf *buf = filp->private_data;
	unsigned long flags;

	/* This trylock will only fail after the print driver is destroyed */
	if (_stp_print_trylock_irqsave(&flags)) {
		/* Switch out the current buffer if it has any data */
		if (buf->offset)
			__stp_relay_switch_subbuf(buf, 0);
		_stp_print_unlock_irqrestore(&flags);
	}

	/*
	 * Optimization: bail out early if there's nothing to read. This is
	 * faster than going into relay's read() function without having any
	 * data, as it will acquire a mutex lock for the inode before bailing.
	 */
	if (buf->subbufs_produced == buf->subbufs_consumed)
		return -ENODATA;

	return relay_file_operations.read(filp, buffer, count, ppos);
}

static void __stp_relay_wakeup_readers(struct rchan_buf *buf)
{
	if (buf && waitqueue_active(&buf->read_wait) &&
	    !__stp_relay_buf_empty(buf))
		wake_up_interruptible(&buf->read_wait);
}

static void __stp_relay_wakeup_timer(stp_timer_callback_parameter_t unused)
{
	int i;

	if (atomic_cmpxchg(&_stp_relay_data.wakeup, 1, 0)) {
		struct rchan_buf *buf;
		
		for_each_possible_cpu(i) {
			buf = _stp_get_rchan_subbuf(_stp_relay_data.rchan->buf,
						    i);
			__stp_relay_wakeup_readers(buf);
		}
	}

	if (atomic_read(&_stp_relay_data.transport_state) == STP_TRANSPORT_RUNNING)
        	mod_timer(&_stp_relay_data.timer, jiffies + STP_RELAY_TIMER_INTERVAL);
        else
		dbug_trans(0, "relay_v2 wakeup timer expiry\n");
}

static void __stp_relay_timer_init(void)
{
	atomic_set(&_stp_relay_data.wakeup, 0);
	timer_setup(&_stp_relay_data.timer, __stp_relay_wakeup_timer, 0);
	_stp_relay_data.timer.expires = jiffies + STP_RELAY_TIMER_INTERVAL;
	add_timer(&_stp_relay_data.timer);
	smp_mb();
}

static enum _stp_transport_state _stp_transport_get_state(void)
{
	return atomic_read (&_stp_relay_data.transport_state);
}

static void _stp_transport_data_fs_overwrite(int overwrite)
{
	_stp_relay_data.overwrite_flag = overwrite;
}


/*
 * Keep track of how many times we encountered a full subbuffer, to aid
 * the user space app in telling how many lost events there were.
 */
static int __stp_relay_subbuf_start_callback(struct rchan_buf *buf,
                                             void *subbuf, void *prev_subbuf,
                                             size_t prev_padding)
{
        if (_stp_relay_data.overwrite_flag || !relay_buf_full(buf))
                return 1;
        
#ifdef _STP_USE_DROPPED_FILE
        atomic_inc(&_stp_relay_data.dropped);
#endif
        return 0;
}


// PR26665: demultiplex debugfs vs procfs host

static int __stp_relay_remove_buf_file_callback(struct dentry *dentry)
{
        if (debugfs_p)
                return __stp_debugfs_relay_remove_buf_file_callback(dentry);
        if (procfs_p)
                return __stp_procfs_relay_remove_buf_file_callback(dentry);
	return 0;
}


static struct dentry *
__stp_relay_create_buf_file_callback(const char *filename,
				     struct dentry *parent,
#ifdef STAPCONF_RELAY_UMODE_T
				     umode_t mode,
#else
				     int mode,
#endif
				     struct rchan_buf *buf,
				     int *is_global)
{
        if (debugfs_p)
                return __stp_debugfs_relay_create_buf_file_callback(filename, parent, mode, buf, is_global);
        if (procfs_p)
                return __stp_procfs_relay_create_buf_file_callback(filename, parent, mode, buf, is_global);
        return NULL;
}


static struct rchan_callbacks __stp_relay_callbacks = {
	.subbuf_start		= __stp_relay_subbuf_start_callback,
	.create_buf_file	= __stp_relay_create_buf_file_callback,
	.remove_buf_file	= __stp_relay_remove_buf_file_callback,
};


static void _stp_transport_data_fs_start(void)
{
	if (atomic_read (&_stp_relay_data.transport_state) == STP_TRANSPORT_INITIALIZED) {
		atomic_set (&_stp_relay_data.transport_state, STP_TRANSPORT_RUNNING);
		/* We're initialized.  Now start the timer. */
		__stp_relay_timer_init();
	}
}

static void _stp_transport_data_fs_stop(void)
{

	if (atomic_read (&_stp_relay_data.transport_state) == STP_TRANSPORT_RUNNING) {
		atomic_set (&_stp_relay_data.transport_state, STP_TRANSPORT_STOPPED);
		del_timer_sync(&_stp_relay_data.timer);
		dbug_trans(0, "flushing...\n");
		if (_stp_relay_data.rchan)
			relay_flush(_stp_relay_data.rchan);
	}
}

static void _stp_transport_data_fs_close(void)
{
	_stp_transport_data_fs_stop();
	if (_stp_relay_data.rchan) {
		relay_close(_stp_relay_data.rchan);
		_stp_relay_data.rchan = NULL;
	}
}

static int _stp_transport_data_fs_init(void)
{
	int rc;
	u64 npages;
	struct sysinfo si;

	atomic_set(&_stp_relay_data.transport_state, STP_TRANSPORT_STOPPED);
	_stp_relay_data.overwrite_flag = 0;
	_stp_relay_data.rchan = NULL;

	/* Create "trace" file. */
	npages = _stp_subbuf_size * _stp_nsubbufs;
	npages *= num_online_cpus();
	npages >>= PAGE_SHIFT;
	si_meminfo(&si);
#define MB(i) (unsigned long)((i) >> (20 - PAGE_SHIFT))
	if (npages > (si.freeram + si.bufferram)) {
		errk("Not enough free+buffered memory(%luMB) for log buffer(%luMB)\n",
		     MB(si.freeram + si.bufferram),
		     MB(npages));
		rc = -ENOMEM;
		goto err;
	}
	else if (npages > si.freeram) {
		/* exceeds freeram, but below freeram+bufferram */
		printk(KERN_WARNING
		       "log buffer size exceeds free memory(%luMB)\n",
		       MB(si.freeram));
	}
	relay_file_operations_w_owner = relay_file_operations;
	relay_file_operations_w_owner.owner = THIS_MODULE;
	relay_file_operations_w_owner.poll = __stp_relay_file_poll;
	relay_file_operations_w_owner.read = __stp_relay_file_read;
#if (RELAYFS_CHANNEL_VERSION >= 7)
	_stp_relay_data.rchan = relay_open("trace", _stp_get_module_dir(),
					   _stp_subbuf_size, _stp_nsubbufs,
					   &__stp_relay_callbacks, NULL);
#else  /* (RELAYFS_CHANNEL_VERSION < 7) */
	_stp_relay_data.rchan = relay_open("trace", _stp_get_module_dir(),
					   _stp_subbuf_size, _stp_nsubbufs,
					   &__stp_relay_callbacks);
#endif  /* (RELAYFS_CHANNEL_VERSION < 7) */
	if (!_stp_relay_data.rchan) {
		rc = -ENOENT;
		errk("%s: relay_open() failed: %d\n", THIS_MODULE->name, rc);
		goto err;
	}
        /* Increment _stp_allocated_memory and _stp_allocated_net_memory to account for buffers
           allocated by relay_open. */
        {
                u64 relay_mem;
                relay_mem = _stp_subbuf_size * _stp_nsubbufs;
                relay_mem *= num_online_cpus();
                _stp_allocated_net_memory += relay_mem;
                _stp_allocated_memory += relay_mem;
        }

	dbug_trans(1, "returning 0...\n");
	atomic_set (&_stp_relay_data.transport_state, STP_TRANSPORT_INITIALIZED);

	return 0;

err:
	_stp_transport_data_fs_close();
	return rc;
}


/**
 *      _stp_data_write_reserve - try to reserve size_request bytes
 *      @size_request: number of bytes to attempt to reserve
 *      @entry: entry is returned here
 *
 *      Returns number of bytes reserved, 0 if full.  On return, entry
 *      will point to allocated opaque pointer.  Use
 *      _stp_data_entry_data() to get pointer to copy data into.
 *
 *	(For this code's purposes, entry is filled in with the actual
 *	data pointer, but the caller doesn't know that.)
 */
static size_t
_stp_data_write_reserve(size_t size_request, void **entry)
{
	struct rchan_buf *buf;

	if (entry == NULL)
		return -EINVAL;

	buf = _stp_get_rchan_subbuf(_stp_relay_data.rchan->buf,
				    smp_processor_id());
	if (buf->offset >= buf->chan->subbuf_size) {
		size_request = __stp_relay_switch_subbuf(buf, size_request);
		if (!size_request)
			return 0;
	} else if (buf->offset + size_request > buf->chan->subbuf_size) {
		size_request = buf->chan->subbuf_size - buf->offset;
	}
	*entry = (char*)buf->data + buf->offset;
	buf->offset += size_request;

	return size_request;
}

static unsigned char *_stp_data_entry_data(void *entry)
{
	/* Nothing to do here. */
	return entry;
}

static int _stp_data_write_commit(void *entry)
{
	atomic_set(&_stp_relay_data.wakeup, 1);
	return 0;
}
