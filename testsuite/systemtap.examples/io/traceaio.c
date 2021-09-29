// Test program for traceaio.stp example.
// Copyright (C) 2001 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.
//
// Example usage:
//
//     $ gcc -D_GNU_SOURCE -o traceaio traceaio.c -laio
//
//     $ sudo stap traceaio.stp -c "./traceaio /var/tmp/traceaio.data"
//     Tracing started
//     [     0 traceaio(756217):] io_submit(140589416931328, 4, 0x7ffc6d6bb8a0)
//         iocb[   0]=0x7ffc6d6bb8c0, fd=3, opcode=1, offset=0, nbytes=4096, buf=0x1764000
//         iocb[   1]=0x7ffc6d6bb900, fd=3, opcode=0, offset=4096, nbytes=4096, buf=0x1765000
//         iocb[   2]=0x7ffc6d6bb940, fd=3, opcode=8, offset=8192, nbytes=1, buf=0x7ffc6d6bb880
//             iovec[   0]=0x7ffc6d6bb880, base=0x1766000, len=4096
//         iocb[   3]=0x7ffc6d6bb980, fd=3, opcode=7, offset=12288, nbytes=1, buf=0x7ffc6d6bb890
//             iovec[   0]=0x7ffc6d6bb890, base=0x1767000, len=4096
//     Tracing stopped
//

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <libaio.h>

#define IO_SIZE 4096

int main(int argc, char *argv[])
{
    int fd;
    void *buffer;
    io_context_t ioctx = {0};
    struct iocb iocbs[4];
    struct iocb *iocbp[] = {&iocbs[0], &iocbs[1], &iocbs[2], &iocbs[3]};
    struct iovec iovs[2];
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: traceaio-test FILENAME\n");
        exit(1);
    }

    fd = open(argv[1], O_RDWR | O_CREAT | O_DIRECT, 0644);
    assert(fd != -1);

    err = fallocate(fd, 0, 0, 4 * IO_SIZE);
    assert(err == 0);

    err = posix_memalign(&buffer, IO_SIZE, 4 * IO_SIZE);
    assert(err == 0);

    memset(buffer, 0, 4 * IO_SIZE);

    err = io_setup(128, &ioctx);
    assert(err == 0);

    /* PWRITE */

    io_prep_pwrite(&iocbs[0], fd, buffer + 0 * IO_SIZE, IO_SIZE, 0 * IO_SIZE);

    /* PREAD */

    io_prep_pread(&iocbs[1], fd, buffer + 1 * IO_SIZE, IO_SIZE, 1 * IO_SIZE);

    /* PWRITEV */

    iovs[0].iov_base = buffer + 2 * IO_SIZE;
    iovs[0].iov_len = IO_SIZE;
    io_prep_pwritev(&iocbs[2], fd, &iovs[0], 1, 2 * IO_SIZE);

    /* PREADV */

    iovs[1].iov_base = buffer + 3 * IO_SIZE;
    iovs[1].iov_len = IO_SIZE;
    io_prep_preadv(&iocbs[3], fd, &iovs[1], 1, 3 * IO_SIZE);

    io_submit(ioctx, 4, iocbp);

    io_getevents(ioctx, 4, 4, NULL, NULL);
    io_destroy(ioctx);
    free(buffer);
    close(fd);

    return 0;
}
