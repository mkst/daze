#include "file_attrs.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int daze_dos_file_attrs_get(const DazeDosfsMounts *mounts, const char *guest_path,
                            DazeDosFileAttrs *result) {
  if (mounts == NULL || guest_path == NULL || result == NULL) return 0;
  int fd = -1;
  int host_errno = 0;
  struct stat information;
  if (daze_dosfs_open_c(mounts, guest_path, O_RDONLY, 0, &fd, &host_errno) != DAZE_DOSFS_OK ||
      fstat(fd, &information) != 0) {
    if (fd >= 0) close(fd);
    result->dos_error = host_errno != 0 ? daze_dosfs_errno_to_dos_error(host_errno)
                                        : daze_dosfs_errno_to_dos_error(errno);
    result->successful = 0;
    return 1;
  }
  close(fd);
  result->attributes = S_ISDIR(information.st_mode) ? 0x10 : 0x20;
  result->successful = 1;
  return 1;
}
