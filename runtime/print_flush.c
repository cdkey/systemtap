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
	char *bufp = log->buf;
	size_t len = log->len;
	void *entry = NULL;

	/* check to see if there is anything in the buffer */
	if (likely(len == 0))
		return;

	log->len = 0;
	dbug_trans(1, "len = %zu\n", len);
	do {
		size_t bytes_reserved;

		bytes_reserved = _stp_data_write_reserve(len, &entry);
		if (likely(entry && bytes_reserved)) {
			memcpy(_stp_data_entry_data(entry), bufp,
			       bytes_reserved);
			_stp_data_write_commit(entry);
			bufp += bytes_reserved;
			len -= bytes_reserved;
		} else {
			atomic_inc(&_stp_transport_failures);
			break;
		}
	} while (len > 0);
}
