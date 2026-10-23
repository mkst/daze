#include "exec_loader.h"
#include "exec_image.h"
#include "byte_order.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int descriptor_count(void) {
#if defined(__APPLE__)
  DIR *directory = opendir("/dev/fd");
#else
  DIR *directory = opendir("/proc/self/fd");
#endif
  if (directory == NULL) return -1;
  int count = 0;
  while (readdir(directory) != NULL)
    ++count;
  closedir(directory);
  return count;
}

static int rejected(const DazeDosfsMounts *mounts, const char *path, int expected) {
  DazeImage image = {0};
  int error = 0;
  const int before = descriptor_count();
  errno = EBUSY;
  const int loaded = daze_dos_exec_load_mounted(mounts, path, &image, &error);
  const int pass = !loaded && image.bytes == NULL && image.size == 0 && error == expected &&
                   before >= 0 && descriptor_count() == before;
  if (!pass)
    fprintf(stderr, "mounted EXEC %s: loaded=%d size=%zu errno=%d expected=%d\n",
            path == NULL ? "(null)" : path, loaded, image.size, error, expected);
  daze_image_free(&image);
  return pass;
}

static int generated_image(int root_fd, DazeDosfsMounts *mounts) {
  uint8_t bytes[64] = {'M', 'Z'};
  daze_write_u16(bytes + 2, sizeof(bytes));
  daze_write_u16(bytes + 4, 1);
  daze_write_u16(bytes + 6, 2);
  daze_write_u16(bytes + 8, 3);
  daze_write_u16(bytes + 0x18, 0x1c);
  daze_write_u16(bytes + 0x20, 15);
  daze_write_u16(bytes + 0x30, 0x1234);
  const int fd = openat(root_fd, "BAD.EXE", O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) return 0;
  const int written = write(fd, bytes, sizeof(bytes)) == sizeof(bytes);
  close(fd);
  DazeImage image = {0};
  int error = 0;
  int pass = written && daze_dos_exec_load_mounted(mounts, "c:bad.exe", &image, &error) &&
             error == 0 && image.size == sizeof(bytes) &&
             memcmp(image.bytes, bytes, sizeof(bytes)) == 0;
  DazeMzHeader header;
  if (pass) {
    uint8_t *prepared = NULL;
    size_t prepared_size = 0xa5a5;
    pass =
      daze_mz_parse_header(image.bytes, image.size, &header) &&
      !daze_dos_exec_image_prepare(&image, &header, 0x3010, 0x100000, &prepared, &prepared_size) &&
      prepared == NULL && prepared_size == 0xa5a5 && memcmp(image.bytes, bytes, sizeof(bytes)) == 0;
    free(prepared);
  }
  daze_image_free(&image);
  daze_image_free(&image);
  pass = pass && image.bytes == NULL && image.size == 0;
  const int empty_fd = openat(root_fd, "EMPTY.EXE", O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (empty_fd < 0) return 0;
  close(empty_fd);
  pass = pass && daze_dos_exec_load_mounted(mounts, "EMPTY.EXE", &image, &error) && error == 0 &&
         image.bytes != NULL && image.size == 0 && !daze_mz_parse_header(image.bytes, 0, &header);
  daze_image_free(&image);
  return pass;
}

int main(void) {
  char root[] = "/tmp/daze-exec-loader-XXXXXX";
  if (mkdtemp(root) == NULL) return 1;
  const int root_fd = open(root, O_RDONLY | O_DIRECTORY);
  if (root_fd < 0) return 1;
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  int pass = daze_dosfs_mounts_add_named(&mounts, 2, root_fd, 1) == DAZE_DOSFS_OK &&
             mkdirat(root_fd, "DIR", 0700) == 0 && symlinkat("/", root_fd, "LINK") == 0;
  pass = generated_image(root_fd, &mounts) && pass;
  const int before = descriptor_count();
  DazeImage image = {0};
  int error = 123;
  pass = pass && !daze_dos_exec_load_mounted(&mounts, "BAD.EXE", NULL, &error) && error == 123 &&
         !daze_dos_exec_load_mounted(&mounts, "BAD.EXE", &image, NULL) && image.bytes == NULL;
  const struct {
    const char *path;
    int error;
  } failures[] = {
    {NULL, EINVAL},
    {"1:BAD.EXE", EINVAL},
    {"D:BAD.EXE", EINVAL},
    {"MISSING.EXE", ENOENT},
    {"MISSING/BAD.EXE", ENOENT},
    {"BAD.EXE/CHILD.EXE", ENOTDIR},
    {"LINK", ELOOP},
    {"DIR", EISDIR},
  };
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i)
    pass = rejected(&mounts, failures[i].path, failures[i].error) && pass;
  pass = rejected(NULL, "BAD.EXE", EINVAL) && pass;
  pass = pass && descriptor_count() == before;
  unlinkat(root_fd, "BAD.EXE", 0);
  unlinkat(root_fd, "EMPTY.EXE", 0);
  unlinkat(root_fd, "LINK", 0);
  unlinkat(root_fd, "DIR", AT_REMOVEDIR);
  close(root_fd);
  rmdir(root);
  fprintf(stderr, "Mounted EXEC loader contract: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
