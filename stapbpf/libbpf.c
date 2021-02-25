/* eBPF mini library */
#include <stdlib.h>
#include <stdio.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/bpf.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/perf_event.h>
#include <arpa/inet.h>
#include "libbpf.h"

/* Older headers might not have this defined yet. */
#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# else
#  error __NR_bpf not defined.
# endif
#endif

static __u64 ptr_to_u64(void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

int bpf_create_map(enum bpf_map_type map_type, unsigned key_size,
		   unsigned value_size, unsigned max_entries,
		   unsigned flags __attribute__((unused)))
{
	union bpf_attr attr;
        memset(&attr, 0, sizeof(union bpf_attr));
	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags)
{
	union bpf_attr attr;
        memset(&attr, 0, sizeof(union bpf_attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_lookup_elem(int fd, void *key, void *value)
{
	union bpf_attr attr;
        memset(&attr, 0, sizeof(union bpf_attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_delete_elem(int fd, void *key)
{
	union bpf_attr attr;
        memset(&attr, 0, sizeof(union bpf_attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);

	return syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
	union bpf_attr attr;
        memset(&attr, 0, sizeof(union bpf_attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

#define ROUND_UP(x, n) (((x) + (n) - 1u) & ~((n) - 1u))

char bpf_log_buf[LOG_BUF_SIZE];
extern int verbose; // set from stapbpf command line

int bpf_prog_load(enum bpf_prog_type prog_type,
		  const struct bpf_insn *insns, int prog_len,
		  const char *license, int kern_version)
{
	union bpf_attr attr;
        memset (&attr, 0, sizeof(attr)); // kernel asserts 0 pad values
	attr.prog_type = prog_type;
	attr.insns = ptr_to_u64((void *) insns);
	attr.insn_cnt = prog_len / sizeof(struct bpf_insn);
	attr.license = ptr_to_u64((void *) license);

        /* If the syscall fails, retry with higher verbosity to get
           the eBPF verifier output */
        int retry = 0;
 do_retry:
        if (verbose || retry)
          {
            attr.log_buf = ptr_to_u64(bpf_log_buf);
            attr.log_size = LOG_BUF_SIZE;
            attr.log_level = retry ? verbose + 1 : verbose;
            /* they hang together, or they hang separately with -EINVAL */
          }

	/* assign one field outside of struct init to make sure any
	 * padding is zero initialized
	 */
	attr.kern_version = kern_version;

	bpf_log_buf[0] = 0;

        if (verbose > 1)
          fprintf(stderr, "Loading probe type %d, size %d\n", prog_type, prog_len);

        int rc = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
        if (rc < 0 && verbose == 0 && !retry)
          {
            retry = 1; goto do_retry;
          }
        return rc;
}

int bpf_obj_pin(int fd, const char *pathname)
{
	union bpf_attr attr;
        memset(&attr, 0, sizeof(union bpf_attr));
	attr.pathname	= ptr_to_u64((void *)pathname);
	attr.bpf_fd	= fd;

	return syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}

// XXX experimental, imitates tools/include/linux/ring_buffer.h and bcc
static inline __u64
ring_buffer_read_head(volatile struct perf_event_mmap_page *base)
{
        __u64 head = base->data_head;
        asm volatile ("" ::: "memory"); // memory fence
        return head;
}

// XXX experimental, imitates tools/include/linux/ring_buffer.h and bcc
static inline void
ring_buffer_write_tail(volatile struct perf_event_mmap_page *base,
                       __u64 tail)
{
        asm volatile("" ::: "memory"); // memory fence
        base->data_tail = tail;
}


enum bpf_perf_event_ret
bpf_perf_event_read_simple(void *mmap_mem, size_t mmap_size, size_t page_size,
                           void **copy_mem, size_t *copy_size,
                           bpf_perf_event_print_t fn, void *private_data)
{
        struct perf_event_mmap_page *header = mmap_mem;
        __u64 data_head = ring_buffer_read_head(header);
        __u64 data_tail = header->data_tail;
        void *base = ((__u8 *)header) + page_size;
        int ret = LIBBPF_PERF_EVENT_CONT;
        struct perf_event_header *ehdr;
        size_t ehdr_size;

        while (data_head != data_tail) {
                ehdr = base + (data_tail & (mmap_size - 1));
                ehdr_size = ehdr->size;

                if (((void *)ehdr) + ehdr_size > base + mmap_size) {
                        void *copy_start = ehdr;
                        size_t len_first = base + mmap_size - copy_start;
                        size_t len_secnd = ehdr_size - len_first;

                        if (*copy_size < ehdr_size) {
                                free(*copy_mem);
                                *copy_mem = malloc(ehdr_size);
                                if (!*copy_mem) {
                                        *copy_size = 0;
                                        ret = LIBBPF_PERF_EVENT_ERROR;
                                        break;
                                }
                                *copy_size = ehdr_size;
                        }

                        memcpy(*copy_mem, copy_start, len_first);
                        memcpy(*copy_mem + len_first, base, len_secnd);
                        ehdr = *copy_mem;
                }

                ret = fn(ehdr, private_data);
                data_tail += ehdr_size;
                if (ret != LIBBPF_PERF_EVENT_CONT)
                        break;
        }

        ring_buffer_write_tail(header, data_tail);
        return ret;
}

int bpf_obj_get(const char *pathname)
{
	union bpf_attr attr;
        memset(&attr, 0, sizeof(union bpf_attr));
	attr.pathname = ptr_to_u64((void *)pathname);

	return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		printf("cannot create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

int perf_event_open(struct perf_event_attr *attr, int pid, int cpu,
		    int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu,
		       group_fd, flags);
}
