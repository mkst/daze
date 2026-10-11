#include "exec_loader.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int daze_dos_exec_load_mounted(const DazeDosfsMounts *mounts, const char *path, DazeImage *image,
                               int *host_errno) {
  int fd = -1;
  struct stat status;
  if (image == NULL || host_errno == NULL) return 0;
  *image = (DazeImage){0};
  *host_errno = 0;
  if (mounts == NULL || path == NULL) {
    *host_errno = EINVAL;
    return 0;
  }
  if (daze_dosfs_open_c(mounts, path, O_RDONLY, 0, &fd, host_errno) != DAZE_DOSFS_OK) {
    if (*host_errno == 0) *host_errno = EINVAL;
    return 0;
  }
  if (fstat(fd, &status) != 0) {
    *host_errno = errno;
    close(fd);
    return 0;
  }
  if (status.st_size < 0 || (uintmax_t)status.st_size > SIZE_MAX) {
    *host_errno = EINVAL;
    close(fd);
    return 0;
  }
  image->size = (size_t)status.st_size;
  image->bytes = malloc(image->size == 0 ? 1 : image->size);
  size_t offset = 0;
  while (image->bytes != NULL && offset < image->size) {
    const ssize_t count = read(fd, image->bytes + offset, image->size - offset);
    if (count > 0) {
      offset += (size_t)count;
    } else if (count < 0 && errno == EINTR) {
      continue;
    } else {
      if (count < 0) *host_errno = errno;
      break;
    }
  }
  close(fd);
  if (image->bytes == NULL || offset != image->size) {
    if (*host_errno == 0) *host_errno = image->bytes == NULL ? ENOMEM : EIO;
    daze_image_free(image);
    return 0;
  }
  return 1;
}
