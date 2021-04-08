//
// The following kernel commit changed the kernel_read() function signature:
//
// commit bdd1d2d3d251c65b74ac4493e08db18971c09240
// Author: Christoph Hellwig <hch@lst.de>
// Date:   Fri Sep 1 17:39:13 2017 +0200
//
//     fs: fix kernel_read prototype
//
//     Use proper ssize_t and size_t types for the return value and count
//     argument, move the offset last and make it an in/out argument like
//     all other read/write helpers, and make the buf argument a void pointer
//     to get rid of lots of casts in the callers.
//
//     Signed-off-by: Christoph Hellwig <hch@lst.de>
//     Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
//
// This changed the function signature from:
//
// int kernel_read(struct file *file, loff_t offset, char *addr,
// 		unsigned long count);
//
// to:
//
// ssize_t kernel_read(struct file *file, void *buf, size_t count, loff_t *pos);
//

#include <linux/fs.h>

ssize_t foo(struct file *file, void *buf, size_t count, loff_t *pos)
{
	return kernel_read(file, buf, count, pos);
}
