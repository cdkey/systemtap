// PR26099: Linux kernel commit d56c0d45f0e for version 5.6 made the following changes:
// - procfs functions now take struct proc_ops instead of struct file_operations
// - proc_dir_entry now has union{proc_ops,proc_dir_ops} instead of proc_fops
//
// XXX: It should be sufficient to test for the existence of struct proc_ops.

#include <linux/fs.h>
#include <linux/proc_fs.h>

int
proc_open_file_test(struct inode *inode, struct file *filp)
{
  return 0;
}

static struct proc_ops proc_ops_test __attribute__ ((unused)) = {
  .proc_open = &proc_open_file_test,
};
