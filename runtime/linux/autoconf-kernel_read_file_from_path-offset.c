//
// The following kernel commit changed the get_user_pages_remote()
// function signature:
//
// commit 0fa8e084648779eeb8929ae004301b3acf3bad84
// Author: Kees Cook <keescook@chromium.org>
// Date:   Fri Oct 2 10:38:25 2020 -0700
//
//    fs/kernel_file_read: Add "offset" arg for partial reads
//
//    To perform partial reads, callers of kernel_read_file*() must have a
//    non-NULL file_size argument and a preallocated buffer. The new "offset"
//    argument can then be used to seek to specific locations in the file to
//    fill the buffer to, at most, "buf_size" per call.
//
//    Where possible, the LSM hooks can report whether a full file has been
//    read or not so that the contents can be reasoned about.
//
// This and the preceding commits changed the function signature from:
//
// int kernel_read_file_from_path(const char *path,
//			       void **buf, loff_t *size, loff_t max_size,
//			       enum kernel_read_file_id id);
//
// to:
//
// int kernel_read_file_from_path(const char *path, loff_t offset,
//			       void **buf, size_t buf_size,
//			       size_t *file_size,
//			       enum kernel_read_file_id id);
//

// XXX kernel commit b89999d004931ab2e51236 also split
// kernel_read_file_* functions into a separate header.
//
// As both changes were merged for v5.10-rc1 within the same day,
// we detect them with the same autoconf program:
#include <linux/kernel_read_file.h>

int krffp_wrapper(const char *path, loff_t offset,
                  void **buf, size_t buf_size,
                  size_t *file_size,
                  enum kernel_read_file_id id)
{
  return kernel_read_file_from_path(path, offset, buf, buf_size, file_size, id);
}
