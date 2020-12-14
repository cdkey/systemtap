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


#ifndef HAVE_OPENAT
#error "need openat"
#endif


// This function does multiple things:
//
// 1) if needed, open the running module's directory (the one that
//    contains .ctl), stash fd in relay_basedir_fd; this will be
//    passed to stapio children via -F$fd for privilege passing
//
// 2) (re)open the running module's .ctl file, stash fd in the
//    control_channel global; this will be used all over the place.
//
// Return 0 on success.
//
// See also PR14245, PR26665, RHBZ1902696 = PR23512
//
int init_ctl_channel(const char *name, int verb)
{
        (void) verb;

        // Already got them both?
        if (control_channel >= 0 && relay_basedir_fd >= 0)
                return 0;

        // Need relay_basedir_fd .... ok try /sys/kernel/debug/systemtap/
        if (relay_basedir_fd < 0) {
                char buf[PATH_MAX] = "";
                struct statfs st;

                if (sprintf_chk(buf, "/sys/kernel/debug/systemtap/%s", name))
                        return -EINVAL;
                
                if (statfs("/sys/kernel/debug", &st) == 0 && (int)st.f_type == (int)DEBUGFS_MAGIC)
                        relay_basedir_fd = open (buf, O_DIRECTORY | O_RDONLY);                        
        }

        // Still need relay_basedir_fd ... ok try /proc/systemtap/
        if (relay_basedir_fd < 0) {
                char buf[PATH_MAX] = "";

                if (sprintf_chk(buf, "/proc/systemtap/%s", name))
                        return -EINVAL;
                
                relay_basedir_fd = open (buf, O_DIRECTORY | O_RDONLY);                        
        }

        // Got relay_basedir_fd, need .ctl
        if (relay_basedir_fd >= 0) {
                // verify that the ctl file is accessible to our real uid/gid
                if (faccessat(relay_basedir_fd, CTL_CHANNEL_NAME, R_OK|W_OK, 0) != 0)
                        return -EPERM;
                
                control_channel = openat_cloexec(relay_basedir_fd,
						 CTL_CHANNEL_NAME, O_RDWR, 0);
        }

        // Fell through
	if (relay_basedir_fd < 0 || control_channel < 0) {
                err(_("Cannot attach to module %s control channel; not running?\n"),
                    name);
                return -EINVAL;
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
