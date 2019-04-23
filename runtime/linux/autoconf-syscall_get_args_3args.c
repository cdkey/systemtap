#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <linux/sched.h>

struct task_struct *task;
struct pt_regs *regs;
unsigned long *args;

void __something(void)
{
	syscall_get_arguments(task, regs, args);
}
