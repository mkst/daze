#include "file_attrs.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
  char template[] = "/tmp/daze-file-attrs-XXXXXX";
  if (mkdtemp(template) == NULL) {
    perror("mkdtemp");
    return 1;
  }
  char path[128];
  snprintf(path, sizeof(path), "%s/PLAIN.TXT", template);
  const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return 1;
  close(fd);
  snprintf(path, sizeof(path), "%s/SUBDIR", template);
  if (mkdir(path, 0755) != 0) return 1;

  const int mount_fd = open(template, O_RDONLY | O_DIRECTORY);
  if (mount_fd < 0) return 1;
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  int drive_index = -1;
  if (daze_dosfs_mounts_add_default(&mounts, mount_fd, 0, &drive_index) != DAZE_DOSFS_OK) return 1;

  DazeDosFileAttrs attrs = {0};
  if (!daze_dos_file_attrs_get(&mounts, "PLAIN.TXT", &attrs) || !attrs.successful ||
      attrs.attributes != 0x20) {
    fprintf(stderr, "file attrs: plain file served=%d attrs=%02x\n", attrs.successful,
            attrs.attributes);
    return 1;
  }
  fprintf(stderr, "file attrs: present regular file -> 0x20\n");
  attrs = (DazeDosFileAttrs){0};
  if (!daze_dos_file_attrs_get(&mounts, "SUBDIR", &attrs) || !attrs.successful ||
      attrs.attributes != 0x10) {
    fprintf(stderr, "file attrs: directory served=%d attrs=%02x\n", attrs.successful,
            attrs.attributes);
    return 1;
  }
  fprintf(stderr, "file attrs: source-dir mount -> 0x10\n");
  attrs = (DazeDosFileAttrs){0};
  if (!daze_dos_file_attrs_get(&mounts, "MISSING.TXT", &attrs) || attrs.successful ||
      attrs.dos_error == 0) {
    fprintf(stderr, "file attrs: missing served=%d dos_error=%u\n", attrs.successful,
            attrs.dos_error);
    return 1;
  }
  fprintf(stderr, "file attrs: missing file -> DOS error %u, carry set\n", attrs.dos_error);
  if (daze_dos_file_attrs_get(NULL, "PLAIN.TXT", &attrs) ||
      daze_dos_file_attrs_get(&mounts, NULL, &attrs) ||
      daze_dos_file_attrs_get(&mounts, "PLAIN.TXT", NULL)) {
    fprintf(stderr, "file attrs: null-input contract violation not rejected\n");
    return 1;
  }
  if (daze_dos_file_attrs_set(NULL, "PLAIN.TXT", 0, &attrs) ||
      daze_dos_file_attrs_set(&mounts, NULL, 0, &attrs) ||
      daze_dos_file_attrs_set(&mounts, "PLAIN.TXT", 0, NULL)) {
    fprintf(stderr, "file attrs set: null-input contract violation not rejected\n");
    return 1;
  }
  fprintf(stderr, "file attrs: null inputs rejected\n");
  return 0;
}
