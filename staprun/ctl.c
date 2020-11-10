/* -*- linux-c -*-
 *
 * ctl.c - staprun control channel
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 *
 * Copyright (C) 2012-2018 Red Hat Inc.
 */

#include "staprun.h"

#define CTL_CHANNEL_NAME ".cmd"

int init_ctl_channel(const char *name, int verb)
{
	char buf[PATH_MAX] = ""; // the .ctl file name
        char buf2[PATH_MAX] = ""; // other tmp stuff
	struct statfs st;

        (void) verb;
        if (0) goto out; /* just to defeat gcc warnings */

	/* Before trying to open the control channel, make sure it
	 * isn't already open. */
	close_ctl_channel();

#ifdef HAVE_OPENAT
        if (relay_basedir_fd >= 0) {
                strncpy(buf, CTL_CHANNEL_NAME, PATH_MAX - 1);
                control_channel = openat_cloexec(relay_basedir_fd,
						 CTL_CHANNEL_NAME, O_RDWR, 0);
                dbug(2, "Opened %s (%d)\n", CTL_CHANNEL_NAME, control_channel);

                /* NB: Extra real-id access check as below */
                if (faccessat(relay_basedir_fd, CTL_CHANNEL_NAME, R_OK|W_OK, 0) != 0){
                        close(control_channel);
                        return -5;
                }
                if (control_channel >= 0)
                        goto out; /* It's OK to bypass the [f]access[at] check below,
                                     since this would only occur the *second* time 
                                     staprun tries this gig, or within unprivileged stapio. */
        }
        /* PR14245, NB: we fall through to /sys ... /proc searching,
           in case the relay_basedir_fd option wasn't given (i.e., for
           early in staprun), or if errors out for some reason. */
#endif


        // See if we have the .ctl file in debugfs
        if (sprintf_chk(buf2, "/sys/kernel/debug/systemtap/%s/%s", 
                        name, CTL_CHANNEL_NAME))
                return -1;
	if (statfs("/sys/kernel/debug", &st) == 0 && (int)st.f_type == (int)DEBUGFS_MAGIC &&
            (access (buf2, W_OK)==0)) {
                /* PR14245: allow subsequent operations, and if
                   necessary, staprun->stapio forks, to reuse an fd for 
                   directory lookups (even if some parent directories have
                   perms 0700. */
                strcpy(buf, buf2); // committed

#ifdef HAVE_OPENAT
                if (! sprintf_chk(buf2, "/sys/kernel/debug/systemtap/%s", name)) {
                        relay_basedir_fd = open (buf2, O_DIRECTORY | O_RDONLY);
                }
#endif
        }

        // PR26665: try /proc/systemtap/... also
        // (STP_TRANSPORT_1 used to use this for other purposes.)
        if (sprintf_chk(buf2, "/proc/systemtap/%s/%s", 
                        name, CTL_CHANNEL_NAME))
                return -1;
        if (relay_basedir_fd < 0 && (access(buf2, W_OK)==0)) {
                strcpy(buf, buf2); // committed
                
#ifdef HAVE_OPENAT
                if (! sprintf_chk(buf2, "/proc/systemtap/%s", name)) {
                        relay_basedir_fd = open (buf2, O_DIRECTORY | O_RDONLY);
                }
#endif
        }

        /* At this point, we have buf, which is the full path to the .ctl file,
           and we may have a relay_basedir_fd, which is useful to pass across
           staprun->stapio fork/execs. */
        
	control_channel = open_cloexec(buf, O_RDWR, 0);
	dbug(2, "Opened %s (%d)\n", buf, control_channel);

	/* NB: Even if open() succeeded with effective-UID permissions, we
	 * need the access() check to make sure real-UID permissions are also
	 * sufficient.  When we run under the setuid staprun, effective and
	 * real UID may not be the same.  Specifically, we want to prevent 
         * a local stapusr from trying to attach to a different stapusr's module.
	 *
	 * The access() is done *after* open() to avoid any TOCTOU-style race
	 * condition.  We believe it's probably safe either way, as the file
	 * we're trying to access connot be modified by a typical user, but
	 * better safe than sorry.
	 */
#ifdef HAVE_OPENAT
        if (control_channel >= 0 && relay_basedir_fd >= 0) {
                if (faccessat (relay_basedir_fd, CTL_CHANNEL_NAME, R_OK|W_OK, 0) == 0)
                        goto out;
                /* else fall through */
        }
#endif
	if (control_channel >= 0 && access(buf, R_OK|W_OK) != 0) {
		close(control_channel);
		return -5;
	}

out:
	if (control_channel < 0) {
                err(_("Cannot attach to module %s control channel; not running?\n"),
                    name);
		return -3;
	}
	return 0;
}

void close_ctl_channel(void)
{
	if (control_channel >= 0) {
          	dbug(2, "Closed ctl fd %d\n", control_channel);
		close(control_channel);
		control_channel = -1;
	}
}
