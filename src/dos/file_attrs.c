#include "file_attrs.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dos_error.h"

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

int daze_dos_file_attrs_set(const DazeDosfsMounts *mounts, const char *guest_path,
                            uint16_t attributes, DazeDosFileAttrs *result) {
  if (mounts == NULL || guest_path == NULL || result == NULL) return 0;

  /* Daze currently exposes files as normal/archive and directories as
   * directory. CX=0 is the normal-file attribute request used by CC1PSX;
   * it has no host-side state to change. Other DOS attribute bits do not yet
   * have a host representation. */
  if (attributes != 0) {
    result->successful = 0;
    result->dos_error = DAZE_DOS_ERR_ACCESS_DENIED;
    return 1;
  }

  int drive = mounts->default_drive;
  if (guest_path[0] != '\0' && guest_path[1] == ':') {
    const int letter = toupper((unsigned char)guest_path[0]) - 'A';
    if (letter < 0 || letter >= DAZE_DOSFS_MAX_DRIVES) {
      result->successful = 0;
      result->dos_error = DAZE_DOS_ERR_INVALID_DRIVE;
      return 1;
    }
    drive = letter;
  }
  if (daze_dosfs_mount_is_readonly(mounts, drive)) {
    result->successful = 0;
    result->dos_error = DAZE_DOS_ERR_ACCESS_DENIED;
    return 1;
  }

  DazeDosFileAttrs existing;
  if (!daze_dos_file_attrs_get(mounts, guest_path, &existing)) return 0;
  *result = existing;
  return 1;
}
