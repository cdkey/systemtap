#include <linux/kprobes.h>

void* foo(struct kretprobe_instance* ri)
{
        return get_kretprobe(ri);
}
