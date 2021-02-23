/* -*- linux-c -*-
 *
 * start_cmd - cleanly launch a child process
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 *
 * Copyright (C) 2005-2021 Red Hat Inc.
 */

#include "staprun.h"
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <limits.h>
#include <search.h>
#include <wordexp.h>


#define WORKAROUND_BZ467568 1  /* PR 6964; XXX: autoconf when able; also in mainloop.c */

#ifndef OPEN_MAX
#define OPEN_MAX 256
#endif

void
closefrom(int lowfd)
{
  long fd, maxfd;
  char *endp;
  struct dirent *dent;
  DIR *dirp;

  /* Check for a /proc/self/fd directory. */
  if ((dirp = opendir("/proc/self/fd"))) {
    int dir_fd = dirfd(dirp);
    while ((dent = readdir(dirp)) != NULL) {
      fd = strtol(dent->d_name, &endp, 10);
      if (dent->d_name != endp && *endp == '\0'
          && fd >= 0 && fd < INT_MAX && fd >= lowfd
          && fd != dir_fd)
        (void) close((int)fd);
    }
    (void) closedir(dirp);
  }
  else {
    /*
     * Here we fall back on sysconf(). Why? It is possible
     * /proc isn't mounted, we're out of file descriptors,
     * etc., which could cause the opendir() to fail. Also
     * note thet it is possible to open a file descriptor
     * and then drop the rlimit such that it is below the
     * open fd.
     */
    maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0)
      maxfd = OPEN_MAX;

    for (fd = lowfd; fd < maxfd; fd++)
      (void) close((int) fd);
  }
}

#if WORKAROUND_BZ467568
/* When a SIGUSR1 signal arrives, set this variable. */
volatile sig_atomic_t usr1_interrupt = 0;

static void signal_usr1(int signum)
{
  (void) signum;
  usr1_interrupt = 1;
}
#else
static void signal_usr1(int signum)
{
  (void) signum;
}
#endif	/* WORKAROUND_BZ467568 */

/*
 * start_cmd forks the command given on the command line with the "-c"
 * option. It will wait just at the cusp of the exec until the
 * stap module is ready to let it run.  We do it this way because we
 * must have the pid of the forked command so it can be set to the
 * module and made available internally as _stp_target.  PTRACE_DETACH
 * is sent from resume_cmd() below when it receives STP_START from
 * the module.
 */
void start_cmd(void)
{
  pid_t pid;
  struct sigaction a;
#if WORKAROUND_BZ467568
  struct sigaction usr1_action, old_action;
  sigset_t blockmask, oldmask;
#endif	/* WORKAROUND_BZ467568 */

  /* if we are execing a target cmd, ignore ^C in stapio */
  /* and let the target cmd get it. */
  memset(&a, 0, sizeof(a));
  sigemptyset(&a.sa_mask);
  a.sa_flags = 0;
  a.sa_handler = SIG_IGN;
  sigaction(SIGINT, &a, NULL);

#if WORKAROUND_BZ467568
  /* Set up the mask of signals to temporarily block. */
  sigemptyset (&blockmask);
  sigaddset (&blockmask, SIGUSR1);

  /* Establish the SIGUSR1 signal handler. */
  memset(&usr1_action, 0, sizeof(usr1_action));
  sigfillset (&usr1_action.sa_mask);
  usr1_action.sa_flags = 0;
  usr1_action.sa_handler = signal_usr1;
  sigaction (SIGUSR1, &usr1_action, &old_action);

  /* Block SIGUSR1 */
  sigprocmask(SIG_BLOCK, &blockmask, &oldmask);
#endif	/* WORKAROUND_BZ467568 */

  if ((pid = fork()) < 0) {
    _perr("fork");
    exit(1);
  } else if (pid == 0) {
    /* We're in the target process.
     * Let's start the execve of target_cmd. */
    int rc;
    wordexp_t words;
    char *sh_c_argv[4] = { NULL, NULL, NULL, NULL };

    a.sa_handler = SIG_DFL;
    sigaction(SIGINT, &a, NULL);

    /* Close any FDs we still hold, similarly as though this were
     * a program being spawned due to an system("") tapset function. */
    closefrom(3);

    /* We could call closefrom() here, to make sure we don't leak any
     * fds to the target, but it really isn't needed here since
     * close-on-exec should catch everything. We don't have the
     * synchronizations issues here we have with system_cmd(). */

    /* Formerly, we just execl'd(sh,-c,$target_cmd).  But this does't
       work well if target_cmd is a shell builtin.  We really want to
       probe a new child process, not a mishmash of shell-interpreted
       stuff. */
    rc = wordexp (target_cmd, & words, WRDE_NOCMD|WRDE_UNDEF);
    if (rc == WRDE_BADCHAR)
      {
        /* The user must have used a shell metacharacter, thinking that
           we use system(3) to evaluate 'stap -c CMD'.  We could generate
           an error message ... but let's just do what the user meant.
           rhbz 467652. */
        sh_c_argv[0] = "sh";
        sh_c_argv[1] = "-c";
        sh_c_argv[2] = target_cmd;
        sh_c_argv[3] = NULL;

        if (read_stdin)
          {
            /* close target_cmd's stdin to prevent a data race */
            char *buf = malloc(sizeof(char) * (strlen(target_cmd) + 13));
            if (buf == NULL)
              {
                 _err (_("Failed to allocate memory.\n"));
                 _exit(1);
              }
            sprintf(buf, "%s < /dev/null", target_cmd);
            target_cmd = buf;
          }
      }
    else
      {
        switch (rc)
          {
          case 0:
            break;
          case WRDE_SYNTAX:
            _err (_("wordexp: syntax error (unmatched quotes?) in -c COMMAND\n"));
            _exit(1);
          default:
            _err (_("wordexp: parsing error (%d)\n"), rc);
            _exit (1);
          }
        if (words.we_wordc < 1) { _err ("empty -c COMMAND"); _exit (1); }
      }

/* PR 6964: when tracing all the user space process including the
   child the signal will be messed due to uprobe module or utrace
   bug. The kernel sometimes crashes.  So as an alternative
   approximation, we just wait here for a signal from the parent. */

    dbug(1, "blocking briefly\n");
    alarm(60); /* but not indefinitely */

#if WORKAROUND_BZ467568
    {
      /* Wait for the SIGUSR1 */
      while (!usr1_interrupt)
	  sigsuspend(&oldmask);

      /* Restore the old SIGUSR1 signal handler. */
      sigaction (SIGUSR1, &old_action, NULL);

      /* Restore the original signal mask */
      sigprocmask(SIG_SETMASK, &oldmask, NULL);
    }
#else  /* !WORKAROUND_BZ467568 */
    rc = ptrace (PTRACE_TRACEME, 0, 0, 0);
    if (rc < 0) perror ("ptrace me");
    raise (SIGCONT); /* Harmless; just passes control to parent. */
#endif /* !WORKAROUND_BZ467568 */

    alarm(0); /* clear alarms */
    dbug(1, "execing target_cmd %s\n", target_cmd);

    /* Note that execvp() is not a direct system call; it does a $PATH
       search in glibc.  We would like to filter out these dummy syscalls
       from the utrace events seen by scripts.

       This filtering would be done for us for free, if we used ptrace
       ...  but see PR6964.  XXX: Instead, we could open-code the
       $PATH search here; put the pause() afterward; and run a direct
       execve instead of execvp().  */

    if (execvp ((sh_c_argv[0] == NULL ? words.we_wordv[0] : sh_c_argv[0]),
                (sh_c_argv[0] == NULL ? words.we_wordv    : sh_c_argv)) < 0)
      perror(target_cmd);

      /* (There is no need to wordfree() words; they are or will be gone.) */

    _exit(1);
  } else {
    /* We're in the parent.  The child will parse target_cmd and
       execv() the result.  It will be stopped thereabouts and send us
       a SIGTRAP.  Or rather, due to PR 6964, it will stop itself and wait for
       us to release it. */
    target_pid = pid;
#if WORKAROUND_BZ467568
    /* Restore the old SIGUSR1 signal handler. */
    sigaction (SIGUSR1, &old_action, NULL);

    /* Restore the original signal mask */
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
#else  /* !WORKAROUND_BZ467568 */
    int status;
    waitpid (target_pid, &status, 0);
    dbug(1, "waited for target_cmd %s pid %d status %x\n", target_cmd, target_pid, (unsigned) status);
#endif /* !WORKAROUND_BZ467568 */
  }
}

/*
 * resume_cmd signals the command started by start_cmd()
 * and identified by target_pid to continue running.
 * Returns 0 on success, negative PTRACE_DETACH error code on failure. */
int resume_cmd(void)
{
#if WORKAROUND_BZ467568
  /* Let's just send our pet signal to the child
     process that should be waiting for us, mid-pause(). */
  kill (target_pid, SIGUSR1);
#else
  /* Were it not for PR6964, we'd like to do it this way: */
  int rc = ptrace (PTRACE_DETACH, target_pid, 0, 0);
  if (rc < 0)
    {
      perror (_("ptrace detach"));
      if (target_cmd)
        kill(target_pid, SIGKILL);
      return rc;
    }
#endif
  return 0;
}
