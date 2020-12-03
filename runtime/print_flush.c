/* -*- linux-c -*- 
 * Print Flush Function
 * Copyright (C) 2007-2008 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

/** Send the print buffer to the transport now.
 * Output accumulates in the print buffer until it
 * is filled, or this is called. This MUST be called before returning
 * from a probe or accumulated output in the print buffer will be lost.
 *
 * @note Interrupts must be disabled to use this.
 */

static void __stp_print_flush(struct _stp_log *log)
{
	size_t len = log->len;
	void *entry = NULL;

	/* check to see if there is anything in the buffer */
	if (likely(len == 0))
		return;

	log->len = 0;

	dbug_trans(1, "len = %zu\n", len);

#ifdef STP_BULKMODE
#ifdef NO_PERCPU_HEADERS
	{
		char *bufp = log->buf;
		int inode_locked;

		if (!(inode_locked = _stp_transport_trylock_relay_inode())) {
			atomic_inc (&_stp_transport_failures);
#ifndef STP_TRANSPORT_RISKY
			return;
#endif
		}

		while (len > 0) {
			size_t bytes_reserved;

			bytes_reserved = _stp_data_write_reserve(len, &entry);
			if (likely(entry && bytes_reserved > 0)) {
				memcpy(_stp_data_entry_data(entry), bufp,
				       bytes_reserved);
				_stp_data_write_commit(entry);
				bufp += bytes_reserved;
				len -= bytes_reserved;
			}
			else {
				atomic_inc(&_stp_transport_failures);
				break;
			}
		}

		if (inode_locked)
			_stp_transport_unlock_relay_inode();
	}

#else  /* !NO_PERCPU_HEADERS */

	{
		char *bufp = log->buf;
		struct _stp_trace t = {	.sequence = _stp_seq_inc(),
					.pdu_len = len};
		size_t bytes_reserved;
		int inode_locked;

		if (!(inode_locked = _stp_transport_trylock_relay_inode())) {
			atomic_inc (&_stp_transport_failures);
#ifndef STP_TRANSPORT_RISKY
			return;
#endif
		}

		bytes_reserved = _stp_data_write_reserve(sizeof(struct _stp_trace), &entry);
		if (likely(entry && bytes_reserved > 0)) {
			/* prevent unaligned access by using memcpy() */
			memcpy(_stp_data_entry_data(entry), &t, sizeof(t));
			_stp_data_write_commit(entry);
		}
		else {
			atomic_inc(&_stp_transport_failures);
			goto done;
		}

		while (len > 0) {
			bytes_reserved = _stp_data_write_reserve(len, &entry);
			if (likely(entry && bytes_reserved > 0)) {
				memcpy(_stp_data_entry_data(entry), bufp,
				       bytes_reserved);
				_stp_data_write_commit(entry);
				bufp += bytes_reserved;
				len -= bytes_reserved;
			}
			else {
				atomic_inc(&_stp_transport_failures);
				break;
			}
		}

	done:

		if (inode_locked)
			_stp_transport_unlock_relay_inode();
	}
#endif /* !NO_PERCPU_HEADERS */

#else  /* !STP_BULKMODE */

	{
		char *bufp = log->buf;
		int inode_locked;

		if (!(inode_locked = _stp_transport_trylock_relay_inode())) {
			atomic_inc (&_stp_transport_failures);
#ifndef STP_TRANSPORT_RISKY
			dbug_trans(0, "discarding %zu bytes of data\n", len);
			return;
#endif
		}

		dbug_trans(1, "calling _stp_data_write...\n");
		while (len > 0) {
			size_t bytes_reserved;

			bytes_reserved = _stp_data_write_reserve(len, &entry);
			if (likely(entry && bytes_reserved > 0)) {
				memcpy(_stp_data_entry_data(entry), bufp,
				       bytes_reserved);
				_stp_data_write_commit(entry);
				bufp += bytes_reserved;
				len -= bytes_reserved;
			}
			else {
			    atomic_inc(&_stp_transport_failures);
			    break;
			}
		}

		if (inode_locked)
			_stp_transport_unlock_relay_inode();
	}
#endif /* !STP_BULKMODE */
}
