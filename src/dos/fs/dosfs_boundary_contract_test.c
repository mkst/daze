#include "dosfs.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef NDEBUG
#undef assert
#define assert(expression) ((expression) ? (void)0 : abort())
#endif

static void path_contract(void) {
  char root[] = "/tmp/daze-dosfs-boundary-XXXXXX";
  assert(mkdtemp(root) != NULL);
  int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(root_fd >= 0);
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  assert(daze_dosfs_mounts_add_default(&mounts, root_fd, 0, NULL) == DAZE_DOSFS_OK);
  assert(mkdirat(root_fd, "Nested", 0700) == 0);
  assert(mkdirat(root_fd, "Nested/Child", 0700) == 0);
  int fd = openat(root_fd, "Nested/KEEP.TXT", O_CREAT | O_WRONLY | O_EXCL, 0600);
  assert(fd >= 0 && write(fd, "keep", 4) == 4 && close(fd) == 0);
  fd = openat(root_fd, "Nested/Child/DROP.TXT", O_CREAT | O_WRONLY | O_EXCL, 0600);
  assert(fd >= 0 && close(fd) == 0);
  int error = 0, output = -1;
  assert(daze_dosfs_open_c(&mounts, "Nested/Child/../keep.txt", O_RDONLY, 0, &output, &error) ==
         DAZE_DOSFS_OK);
  char contents[4];
  assert(read(output, contents, sizeof(contents)) == 4 && memcmp(contents, "keep", 4) == 0);
  assert(close(output) == 0);
  assert(daze_dosfs_unlink_c(&mounts, "nested\\child\\drop.txt", &error) == DAZE_DOSFS_OK);
  assert(faccessat(root_fd, "Nested/Child/DROP.TXT", F_OK, 0) < 0 && errno == ENOENT);
  assert(daze_dosfs_unlink_c(&mounts, "Nested/absent.txt", &error) == DAZE_DOSFS_HOST_ERROR &&
         error == ENOENT);
  assert(daze_dosfs_unlink_c(&mounts, "absent/drop.txt", &error) == DAZE_DOSFS_HOST_ERROR &&
         error == ENOENT);
  assert(daze_dosfs_unlink_c(&mounts, "Nested/KEEP.TXT/drop.txt", &error) ==
           DAZE_DOSFS_HOST_ERROR &&
         error == ENOTDIR);
  assert(daze_dosfs_unlink_c(&mounts, "C:\\", &error) == DAZE_DOSFS_INVALID_PATH);
  assert(daze_dosfs_unlink_c(&mounts, "bad:path", &error) == DAZE_DOSFS_INVALID_PATH);
  assert(daze_dosfs_open_c(&mounts, "Nested/KEEP.TXT", O_RDONLY, 0, NULL, &error) ==
         DAZE_DOSFS_INVALID_PATH);
  assert(daze_dosfs_open_c(&mounts, "C:\\", O_WRONLY, 0, &output, &error) ==
           DAZE_DOSFS_HOST_ERROR &&
         error == EISDIR);
  for (int drive = -1; drive <= DAZE_DOSFS_MAX_DRIVES; drive += DAZE_DOSFS_MAX_DRIVES + 1) {
    mounts.default_drive = drive;
    assert(daze_dosfs_open_c(&mounts, "file", O_RDONLY, 0, &output, &error) ==
           DAZE_DOSFS_UNMOUNTED_DRIVE);
  }
  mounts.default_drive = 1;
  assert(daze_dosfs_open_c(&mounts, "file", O_RDONLY, 0, &output, &error) ==
         DAZE_DOSFS_UNMOUNTED_DRIVE);
  mounts.default_drive = 2;
  char long_path[DAZE_DOSFS_PATH_MAX + 1];
  memset(long_path, 'a', sizeof(long_path) - 1);
  long_path[sizeof(long_path) - 1] = 0;
  assert(daze_dosfs_open_c(&mounts, long_path, O_RDONLY, 0, &output, &error) ==
         DAZE_DOSFS_OUTPUT_TOO_SMALL);
  assert(daze_dosfs_rename_c(&mounts, NULL, "new.txt", &error) == DAZE_DOSFS_INVALID_PATH);
  assert(daze_dosfs_rename_c(&mounts, "Nested/KEEP.TXT", NULL, &error) == DAZE_DOSFS_INVALID_PATH);
  assert(daze_dosfs_rename_c(&mounts, "", "new.txt", &error) == DAZE_DOSFS_INVALID_PATH);
  assert(daze_dosfs_rename_c(&mounts, "Nested/KEEP.TXT", "", &error) == DAZE_DOSFS_INVALID_PATH);
  char long_leaf[NAME_MAX + 2];
  memset(long_leaf, 'a', sizeof(long_leaf) - 1);
  long_leaf[sizeof(long_leaf) - 1] = '\0';
  assert(daze_dosfs_rename_c(&mounts, "Nested/KEEP.TXT", long_leaf, &error) ==
           DAZE_DOSFS_HOST_ERROR &&
         error == ENAMETOOLONG);
  assert(daze_dosfs_open_c(&mounts, "Nested/KEEP.TXT", O_RDONLY, 0, &output, &error) ==
         DAZE_DOSFS_OK);
  assert(read(output, contents, sizeof(contents)) == 4 && memcmp(contents, "keep", 4) == 0);
  assert(close(output) == 0);
  assert(daze_dosfs_unlink_c(&mounts, "Nested/KEEP.TXT", NULL) == DAZE_DOSFS_OK);
  /* TMP must be creatable through the retained root descriptor. */
  mounts.fds[2] = INT_MAX;
  assert(daze_dosfs_ensure_temp_directory(&mounts, &error) == DAZE_DOSFS_HOST_ERROR &&
         error == EBADF);
  assert(daze_dosfs_unlink_c(&mounts, "file", &error) == DAZE_DOSFS_HOST_ERROR && error == EBADF);
  assert(daze_dosfs_open_c(&mounts, "file", O_RDONLY, 0, &output, &error) ==
           DAZE_DOSFS_HOST_ERROR &&
         error == EBADF);
  mounts.fds[2] = root_fd;
  assert(unlinkat(root_fd, "Nested/Child", AT_REMOVEDIR) == 0);
  assert(unlinkat(root_fd, "Nested", AT_REMOVEDIR) == 0);
  assert(close(root_fd) == 0 && rmdir(root) == 0);
}

static void handle_contract(void) {
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  handles.host_fds[5] = INT_MAX;
  DazeDosfsHandles before = handles;
  int error = 0;
  uint16_t output = 0xbeef;
  assert(daze_dosfs_handles_duplicate(&handles, 5, &output, &error) == DAZE_DOSFS_HOST_ERROR &&
         error == EBADF);
  assert(output == 0xbeef && memcmp(&handles, &before, sizeof(handles)) == 0);
  assert(daze_dosfs_handles_duplicate(&handles, 5, &output, NULL) == DAZE_DOSFS_HOST_ERROR);
  assert(daze_dosfs_handles_force_duplicate(&handles, 5, 6, &error) == DAZE_DOSFS_HOST_ERROR &&
         error == EBADF);
  assert(daze_dosfs_handles_force_duplicate(&handles, 5, 6, NULL) == DAZE_DOSFS_HOST_ERROR);
  assert(memcmp(&handles, &before, sizeof(handles)) == 0);
  int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  assert(fd >= 0);
  handles.host_fds[5] = fd;
  handles.host_fds[6] = INT_MAX;
  before = handles;
  assert(daze_dosfs_handles_force_duplicate(&handles, 5, 6, &error) == DAZE_DOSFS_HOST_ERROR &&
         error == EBADF);
  assert(memcmp(&handles, &before, sizeof(handles)) == 0 && fcntl(fd, F_GETFD) >= 0);
  handles.host_fds[6] = -1;
  daze_dosfs_handles_close_all(&handles);
  assert(fcntl(fd, F_GETFD) < 0 && errno == EBADF);
  DazeDosfsExecHandles scope = {0};
  assert(daze_dosfs_exec_handles_begin(NULL, &handles, NULL) == DAZE_DOSFS_INVALID_PATH);
  assert(daze_dosfs_exec_handles_begin(&scope, NULL, NULL) == DAZE_DOSFS_INVALID_PATH);
  daze_dosfs_exec_handles_restore(NULL);
  daze_dosfs_exec_handles_restore(&scope);
  daze_dosfs_exec_handles_dispose(NULL);
  daze_dosfs_exec_handles_dispose(&scope);
  daze_dosfs_handles_init(NULL);
  daze_dosfs_handles_close_all(NULL);
}

int main(void) {
  path_contract();
  handle_contract();
  char environment[DAZE_DOSFS_ENV_MAX];
  memset(environment, 0xa5, sizeof(environment));
  size_t size = 0xbeef;
  assert(daze_dosfs_default_environment(NULL, sizeof(environment), &size) ==
         DAZE_DOSFS_INVALID_PATH);
  assert(daze_dosfs_default_environment(environment, sizeof(environment), NULL) ==
         DAZE_DOSFS_INVALID_PATH);
  assert(daze_dosfs_default_environment(environment, 1, &size) == DAZE_DOSFS_OUTPUT_TOO_SMALL);
  assert(size == 0xbeef && (unsigned char)environment[0] == 0xa5);
  daze_dosfs_mounts_init(NULL);
  daze_dosfs_find_close(NULL);
  return 0;
}
