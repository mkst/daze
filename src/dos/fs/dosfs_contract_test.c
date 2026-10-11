#include "dosfs.h"
#include "file_service.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int expect_path(const char *guest_path, DazeDosfsStatus expected_status,
                       const char *expected_host_path) {
  char actual[DAZE_DOSFS_PATH_MAX];
  const DazeDosfsStatus status =
    daze_dosfs_resolve_c("/work/toolchain", guest_path, actual, sizeof(actual));
  if (status != expected_status ||
      (status == DAZE_DOSFS_OK && strcmp(actual, expected_host_path) != 0)) {
    fprintf(stderr, "path %s: got %s / %s\n", guest_path, daze_dosfs_status_string(status),
            status == DAZE_DOSFS_OK ? actual : "-");
    return 0;
  }
  return 1;
}

static int exclusive_create_contract(void) {
  char root[] = "/tmp/daze-exclusive-XXXXXX";
  if (mkdtemp(root) == NULL) return 0;
  const int root_fd = open(root, O_RDONLY | O_DIRECTORY);
  int start[2];
  if (root_fd < 0 || pipe(start) != 0) return 0;
  pid_t children[2];
  for (size_t i = 0; i < 2; ++i) {
    children[i] = fork();
    if (children[i] == 0) {
      close(start[1]);
      char token;
      if (read(start[0], &token, 1) != 1) _exit(2);
      DazeDosfsMounts mounts;
      DazeDosfsHandles handles;
      DazeDosfsFileService files;
      DazeDosfsFileResult result;
      daze_dosfs_mounts_init(&mounts);
      daze_dosfs_mounts_add_default(&mounts, root_fd, 0, NULL);
      daze_dosfs_handles_init(&handles);
      daze_dosfs_file_service_init(&files, &mounts, &handles);
      daze_dosfs_file_create_exclusive(&files, "RACE.TMP", &result);
      int status = 2;
      if (result.success) {
        const uint16_t handle = result.handle;
        daze_dosfs_file_write(&files, handle, (const uint8_t *)"retained", 8, &result);
        status = result.success && result.byte_count == 8 ? 0 : 2;
      } else if (result.dos_error == 80) {
        status = 1;
      }
      daze_dosfs_handles_close_all(&handles);
      _exit(status);
    }
  }
  close(start[0]);
  int pass = write(start[1], "xx", 2) == 2;
  close(start[1]);
  int winners = 0, collisions = 0;
  for (size_t i = 0; i < 2; ++i) {
    int status = 0;
    if (children[i] <= 0 || waitpid(children[i], &status, 0) != children[i] || !WIFEXITED(status)) {
      pass = 0;
      continue;
    }
    winners += WEXITSTATUS(status) == 0;
    collisions += WEXITSTATUS(status) == 1;
  }
  const int fd = openat(root_fd, "RACE.TMP", O_RDONLY);
  char bytes[9] = {0};
  pass &= fd >= 0 && read(fd, bytes, sizeof(bytes)) == 8 && strcmp(bytes, "retained") == 0;
  if (fd >= 0) close(fd);
  unlinkat(root_fd, "RACE.TMP", 0);
  close(root_fd);
  rmdir(root);
  return pass && winners == 1 && collisions == 1;
}

static int exec_handles_contract(void) {
  int pipe_fds[2];
  if (pipe(pipe_fds) != 0) return 0;
  close(pipe_fds[1]);
  DazeDosfsHandles live;
  daze_dosfs_handles_init(&live);
  uint16_t handle;
  int host_errno;
  if (daze_dosfs_handles_adopt(&live, pipe_fds[0], &handle) != DAZE_DOSFS_OK) {
    close(pipe_fds[0]);
    return 0;
  }
  DazeDosfsExecHandles scope = {0};
  int pass = daze_dosfs_exec_handles_begin(&scope, &live, &host_errno) == DAZE_DOSFS_OK;
  const int child_fd = live.host_fds[handle];
  pass &= child_fd != pipe_fds[0] &&
          daze_dosfs_exec_handles_begin(&scope, &live, &host_errno) == DAZE_DOSFS_INVALID_PATH;
  daze_dosfs_exec_handles_restore(&scope);
  pass &= scope.live == NULL && live.host_fds[handle] == pipe_fds[0] &&
          fcntl(pipe_fds[0], F_GETFD) != -1 && fcntl(child_fd, F_GETFD) == -1;
  live.host_fds[DAZE_DOSFS_MAX_HANDLES - 1] = INT_MAX;
  pass &= daze_dosfs_exec_handles_begin(&scope, &live, &host_errno) == DAZE_DOSFS_HOST_ERROR &&
          host_errno == EBADF && scope.live == NULL && live.host_fds[handle] == pipe_fds[0];
  live.host_fds[DAZE_DOSFS_MAX_HANDLES - 1] = -1;
  pass &= daze_dosfs_exec_handles_begin(&scope, &live, &host_errno) == DAZE_DOSFS_OK;
  daze_dosfs_exec_handles_dispose(&scope);
  pass &= scope.live == NULL && fcntl(pipe_fds[0], F_GETFD) == -1 &&
          fcntl(live.host_fds[handle], F_GETFD) != -1;
  daze_dosfs_handles_close_all(&live);
  return pass;
}

static int path_rejections_contract(void) {
  char output[16] = "unchanged";
  int pass =
    daze_dosfs_resolve_c(NULL, "TOOL.EXE", output, sizeof(output)) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_resolve_c("relative", "TOOL.EXE", output, sizeof(output)) ==
      DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_resolve_c("/work", NULL, output, sizeof(output)) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_resolve_c("/work", "TOOL.EXE", NULL, sizeof(output)) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_resolve_c("/work", "D:\\TOOL.EXE", output, sizeof(output)) ==
      DAZE_DOSFS_UNMOUNTED_DRIVE &&
    daze_dosfs_resolve_c("/work", "TOOL:EXE", output, sizeof(output)) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_resolve_c("/work", "TOOL.EXE", output, 1) == DAZE_DOSFS_OUTPUT_TOO_SMALL &&
    strcmp(output, "unchanged") == 0;
  if (!pass) fputs("DOS path rejection contract failed\n", stderr);
  return pass;
}

static int mount_rejections_contract(int root_fd) {
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  int pass = daze_dosfs_mounts_add_default(NULL, root_fd, 0, NULL) == DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_mounts_add_default(&mounts, -1, 0, NULL) == DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_mounts_add_named(NULL, 0, root_fd, 0) == DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_mounts_add_named(&mounts, 0, -1, 0) == DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_mounts_add_named(&mounts, -1, root_fd, 0) == DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_mounts_add_named(&mounts, DAZE_DOSFS_MAX_DRIVES, root_fd, 0) ==
               DAZE_DOSFS_INVALID_PATH &&
             !daze_dosfs_mount_is_readonly(NULL, 2) && !daze_dosfs_mount_is_readonly(&mounts, -1) &&
             !daze_dosfs_mount_is_readonly(&mounts, DAZE_DOSFS_MAX_DRIVES) &&
             daze_dosfs_ensure_temp_directory(NULL, NULL) == DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_ensure_temp_directory(&mounts, NULL) == DAZE_DOSFS_INVALID_PATH;

  const int fallback_fd = dup(root_fd);
  int fallback_drive = -1;
  mounts.default_drive = -1;
  pass &=
    fallback_fd >= 0 &&
    daze_dosfs_mounts_add_default(&mounts, fallback_fd, 0, &fallback_drive) == DAZE_DOSFS_OK &&
    fallback_drive == 2 && mounts.default_drive == 2;
  if (mounts.fds[2] >= 0) close(mounts.fds[2]);

  DazeDosfsMounts full;
  daze_dosfs_mounts_init(&full);
  for (int drive = 0; drive < DAZE_DOSFS_MAX_DRIVES; ++drive) {
    const int fd = dup(root_fd);
    if (fd < 0 || daze_dosfs_mounts_add_named(&full, drive, fd, 0) != DAZE_DOSFS_OK) {
      if (fd >= 0) close(fd);
      pass = 0;
      break;
    }
  }
  const DazeDosfsMounts before_full = full;
  const int unowned_fd = dup(root_fd);
  pass &= unowned_fd >= 0 &&
          daze_dosfs_mounts_add_default(&full, unowned_fd, 1, NULL) == DAZE_DOSFS_HOST_ERROR &&
          memcmp(&full, &before_full, sizeof(full)) == 0 && fcntl(unowned_fd, F_GETFD) != -1;
  if (unowned_fd >= 0) close(unowned_fd);
  for (size_t drive = 0; drive < DAZE_DOSFS_MAX_DRIVES; ++drive) {
    if (full.fds[drive] >= 0) close(full.fds[drive]);
  }

  DazeDosfsMounts invalid_default;
  daze_dosfs_mounts_init(&invalid_default);
  invalid_default.default_drive = DAZE_DOSFS_MAX_DRIVES;
  const int invalid_default_fd = dup(root_fd);
  pass &=
    invalid_default_fd >= 0 &&
    daze_dosfs_mounts_add_default(&invalid_default, invalid_default_fd, 0, NULL) == DAZE_DOSFS_OK &&
    invalid_default.default_drive == 2 && invalid_default.fds[2] == invalid_default_fd;
  if (invalid_default.fds[2] >= 0) close(invalid_default.fds[2]);

  if (!pass) fputs("DOS mount rejection contract failed\n", stderr);
  return pass;
}

static int handle_rejections_contract(void) {
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  const int source_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (source_fd < 0) return 0;
  uint16_t handle = 0xbeef;
  int host_errno = 0;
  int pass =
    daze_dosfs_handles_adopt(NULL, source_fd, &handle) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_adopt(&handles, -1, &handle) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_adopt(&handles, source_fd, NULL) == DAZE_DOSFS_INVALID_PATH &&
    handle == 0xbeef && daze_dosfs_handles_get(NULL, 0, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_get(&handles, 0, NULL) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_close(NULL, 0, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_close(&handles, DAZE_DOSFS_MAX_HANDLES, &host_errno) ==
      DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_bind_standard(NULL, 0, 1, 2, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_bind_standard(&handles, -1, 1, 2, &host_errno) == DAZE_DOSFS_INVALID_PATH;

  pass &= daze_dosfs_handles_adopt(&handles, source_fd, &handle) == DAZE_DOSFS_OK && handle == 5;
  int table_fd = -1;
  pass &=
    daze_dosfs_handles_duplicate(&handles, DAZE_DOSFS_MAX_HANDLES, &handle, &host_errno) ==
      DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_duplicate(&handles, 5, NULL, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_force_duplicate(&handles, 99, 8, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_force_duplicate(&handles, 5, DAZE_DOSFS_MAX_HANDLES, &host_errno) ==
      DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_force_duplicate(&handles, 5, 5, &host_errno) == DAZE_DOSFS_OK &&
    daze_dosfs_handles_get(&handles, 5, &table_fd) == DAZE_DOSFS_OK && table_fd == source_fd;

  DazeDosfsHandles occupied_child;
  daze_dosfs_handles_init(&occupied_child);
  const int child_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  pass &= child_fd >= 0;
  if (child_fd >= 0) occupied_child.host_fds[8] = child_fd;
  const DazeDosfsHandles occupied_before = occupied_child;
  pass &=
    daze_dosfs_handles_inherit(NULL, &occupied_child, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_inherit(&handles, NULL, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_inherit(&handles, &handles, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
    daze_dosfs_handles_inherit(&handles, &occupied_child, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
    memcmp(&occupied_child, &occupied_before, sizeof(occupied_child)) == 0;
  daze_dosfs_handles_close_all(&occupied_child);

  DazeDosfsHandles failed_bind;
  daze_dosfs_handles_init(&failed_bind);
  const int retained_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  pass &= retained_fd >= 0;
  if (retained_fd >= 0) failed_bind.host_fds[5] = retained_fd;
  const DazeDosfsHandles failed_bind_before = failed_bind;
  const int hole = open("/dev/null", O_RDONLY | O_CLOEXEC);
  pass &= hole >= 0;
  if (hole >= 0) close(hole);
  pass &= daze_dosfs_handles_bind_standard(&failed_bind, source_fd, INT_MAX, source_fd,
                                           &host_errno) == DAZE_DOSFS_HOST_ERROR &&
          host_errno == EBADF &&
          memcmp(&failed_bind, &failed_bind_before, sizeof(failed_bind)) == 0;
  const int leak_probe = open("/dev/null", O_RDONLY | O_CLOEXEC);
  pass &= leak_probe == hole;
  if (leak_probe >= 0) close(leak_probe);
  daze_dosfs_handles_close_all(&failed_bind);

  handles.host_fds[6] = INT_MAX;
  pass &= daze_dosfs_handles_close(&handles, 6, &host_errno) == DAZE_DOSFS_HOST_ERROR &&
          host_errno == EBADF && handles.host_fds[6] == -1;
  daze_dosfs_handles_close_all(&handles);

  DazeDosfsHandles full;
  daze_dosfs_handles_init(&full);
  const int base_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  pass &= base_fd >= 0;
  for (uint16_t slot = 5; slot < DAZE_DOSFS_MAX_HANDLES && pass; ++slot) {
    const int fd = dup(base_fd);
    uint16_t actual_handle = 0;
    pass &= fd >= 0 && daze_dosfs_handles_adopt(&full, fd, &actual_handle) == DAZE_DOSFS_OK &&
            actual_handle == slot;
    if (!pass && fd >= 0 && full.host_fds[slot] != fd) close(fd);
  }
  const DazeDosfsHandles full_before = full;
  const int extra_fd = dup(base_fd);
  handle = 0xbeef;
  pass &= extra_fd >= 0 &&
          daze_dosfs_handles_adopt(&full, extra_fd, &handle) == DAZE_DOSFS_HOST_ERROR &&
          handle == 0xbeef && fcntl(extra_fd, F_GETFD) != -1;
  if (extra_fd >= 0) close(extra_fd);
  const int leak_hole = open("/dev/null", O_RDONLY | O_CLOEXEC);
  pass &= leak_hole >= 0;
  if (leak_hole >= 0) close(leak_hole);
  pass &= daze_dosfs_handles_duplicate(&full, 5, &handle, &host_errno) == DAZE_DOSFS_HOST_ERROR &&
          host_errno == EMFILE && handle == 0xbeef &&
          memcmp(&full, &full_before, sizeof(full)) == 0;
  const int post_duplicate_probe = open("/dev/null", O_RDONLY | O_CLOEXEC);
  pass &= post_duplicate_probe == leak_hole;
  if (post_duplicate_probe >= 0) close(post_duplicate_probe);
  daze_dosfs_handles_close_all(&full);
  if (base_fd >= 0) close(base_fd);

  if (!pass) fputs("DOS handle rejection contract failed\n", stderr);
  return pass;
}

static int create_file_at(int directory_fd, const char *name) {
  const int fd = openat(directory_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  return fd >= 0 && close(fd) == 0;
}

static int find_listing_contract(const DazeDosfsMounts *mounts) {
  DazeDosfsFind find = {0};
  DazeDosfsFindResult result;
  int found = 0;
  int host_errno = 0;
  int pass = daze_dosfs_find_next(&find, &result, &found, &host_errno) == DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_find_first_c(NULL, "C:\\*.*", 0, &find, &result, &found, &host_errno) ==
               DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_find_first_c(mounts, NULL, 0, &find, &result, &found, &host_errno) ==
               DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_find_first_c(mounts, "C:\\*.*", 0, NULL, &result, &found, &host_errno) ==
               DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_find_first_c(mounts, "C:\\*.*", 0, &find, NULL, &found, &host_errno) ==
               DAZE_DOSFS_INVALID_PATH &&
             daze_dosfs_find_first_c(mounts, "C:\\*.*", 0, &find, &result, NULL, &host_errno) ==
               DAZE_DOSFS_INVALID_PATH;

  struct {
    const char *pattern;
    uint16_t attributes;
    size_t expected_count;
    int include_directories;
  } cases[] = {
    {"C:\\*.*", 0, 3, 0},
    {"C:\\*.*", 0x10, 5, 1},
    {"c:\\d?ta.bin", 0, 1, 0},
    {"C:\\NO-MATCH.*", 0, 0, 0},
  };
  for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    memset(&find, 0, sizeof(find));
    found = -1;
    host_errno = 0;
    DazeDosfsStatus status = daze_dosfs_find_first_c(
      mounts, cases[index].pattern, cases[index].attributes, &find, &result, &found, &host_errno);
    if (status != DAZE_DOSFS_OK || (found != 0) != (cases[index].expected_count != 0)) {
      pass = 0;
    }
    size_t count = 0;
    while (status == DAZE_DOSFS_OK && found) {
      if (strcmp(result.name, "DATA.BIN") != 0 && strcmp(result.name, "Case.TXT") != 0 &&
          strcmp(result.name, "CASE.TXT") != 0 && strcmp(result.name, "SRC") != 0 &&
          strcmp(result.name, "TMP") != 0) {
        pass = 0;
      }
      if (result.name[0] == 'S' || result.name[0] == 'T') {
        pass &= cases[index].include_directories && result.attributes == 0x10 && result.size == 0;
      } else {
        pass &= result.attributes == 0x20 && (strcmp(cases[index].pattern, "c:\\d?ta.bin") != 0 ||
                                              strcmp(result.name, "DATA.BIN") == 0);
      }
      ++count;
      status = daze_dosfs_find_next(&find, &result, &found, &host_errno);
    }
    pass &= status == DAZE_DOSFS_OK && count == cases[index].expected_count && !found;
    daze_dosfs_find_close(&find);
    pass &= find.directory == NULL;
  }

  memset(&find, 0, sizeof(find));
  const char *bad_patterns[] = {"C:\\", "C:\\BAD:*.BIN"};
  for (size_t index = 0; index < sizeof(bad_patterns) / sizeof(bad_patterns[0]); ++index) {
    pass &= daze_dosfs_find_first_c(mounts, bad_patterns[index], 0, &find, &result, &found,
                                    &host_errno) == DAZE_DOSFS_INVALID_PATH &&
            find.directory == NULL;
  }
  char oversized_leaf[DAZE_DOSFS_PATH_MAX + 16];
  memcpy(oversized_leaf, "C:\\", 3);
  memset(oversized_leaf + 3, 'A', sizeof(oversized_leaf) - 3);
  oversized_leaf[sizeof(oversized_leaf) - 1] = '\0';
  pass &= daze_dosfs_find_first_c(mounts, oversized_leaf, 0, &find, &result, &found, &host_errno) ==
          DAZE_DOSFS_INVALID_PATH;

  char oversized_parent[DAZE_DOSFS_PATH_MAX + 8];
  memcpy(oversized_parent, "C:\\", 3);
  memset(oversized_parent + 3, 'A', DAZE_DOSFS_PATH_MAX - 3);
  oversized_parent[DAZE_DOSFS_PATH_MAX - 1] = '\\';
  memcpy(oversized_parent + DAZE_DOSFS_PATH_MAX, "*.BIN", 6);
  pass &= daze_dosfs_find_first_c(mounts, oversized_parent, 0, &find, &result, &found,
                                  &host_errno) == DAZE_DOSFS_OUTPUT_TOO_SMALL;

  host_errno = 0;
  pass &= daze_dosfs_find_first_c(mounts, "C:\\MISSING\\*.BIN", 0, &find, &result, &found,
                                  &host_errno) == DAZE_DOSFS_HOST_ERROR &&
          host_errno == ENOENT && find.directory == NULL;
  host_errno = 0;
  pass &= daze_dosfs_find_first_c(mounts, "C:\\DATA.BIN\\*.BIN", 0, &find, &result, &found,
                                  &host_errno) == DAZE_DOSFS_HOST_ERROR &&
          host_errno == ENOTDIR && find.directory == NULL;
  daze_dosfs_find_close(&find);

  if (!pass) fputs("DOS find-first/find-next contract failed\n", stderr);
  return pass;
}

static int temp_directory_rejections_contract(void) {
  char root[] = "/tmp/daze-dosfs-tmp-contract-XXXXXX";
  if (mkdtemp(root) == NULL) return 0;
  const int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (root_fd < 0) return 0;
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  int pass = daze_dosfs_mounts_add_default(&mounts, root_fd, 0, NULL) == DAZE_DOSFS_OK;
  int host_errno = 0;
  pass &= mkdirat(root_fd, "TMP", 0700) == 0 &&
          daze_dosfs_ensure_temp_directory(&mounts, &host_errno) == DAZE_DOSFS_OK;
  pass &= unlinkat(root_fd, "TMP", AT_REMOVEDIR) == 0 && create_file_at(root_fd, "TMP");
  host_errno = 0;
  pass &= daze_dosfs_ensure_temp_directory(&mounts, &host_errno) == DAZE_DOSFS_HOST_ERROR &&
          host_errno == ENOTDIR;
  pass &= unlinkat(root_fd, "TMP", 0) == 0 && symlinkat("/tmp", root_fd, "TMP") == 0;
  host_errno = 0;
  pass &= daze_dosfs_ensure_temp_directory(&mounts, &host_errno) == DAZE_DOSFS_HOST_ERROR &&
          (host_errno == ELOOP || host_errno == ENOTDIR);
  unlinkat(root_fd, "TMP", 0);
  close(root_fd);
  rmdir(root);
  if (!pass) fputs("DOS temporary-directory rejection contract failed\n", stderr);
  return pass;
}

int main(void) {
  int pass = 1;
  pass &= exec_handles_contract();
  pass &= path_rejections_contract();
  pass &= handle_rejections_contract();
  pass &= temp_directory_rejections_contract();
  pass &= exclusive_create_contract();
  pass &= expect_path("TOOL.EXE", DAZE_DOSFS_OK, "/work/toolchain/TOOL.EXE");
  pass &= expect_path("C:\\SRC\\MIPS.S", DAZE_DOSFS_OK, "/work/toolchain/SRC/MIPS.S");
  pass &= expect_path("c:/TMP/../OUT/FOO.O", DAZE_DOSFS_OK, "/work/toolchain/OUT/FOO.O");
  pass &= expect_path("C:\\..\\..\\TOOL.EXE", DAZE_DOSFS_OK, "/work/toolchain/TOOL.EXE");
  pass &= expect_path("D:\\TOOLS\\X.EXE", DAZE_DOSFS_UNMOUNTED_DRIVE, NULL);
  pass &= expect_path("C:\\BAD:NAME", DAZE_DOSFS_INVALID_PATH, NULL);

  char environment[DAZE_DOSFS_ENV_MAX];
  size_t environment_length = 0;
  static const char expected_environment[] = "PATH=C:\\\0"
                                             "TEMP=C:\\TMP\0"
                                             "TMP=C:\\TMP\0"
                                             "\0";
  const DazeDosfsStatus environment_status =
    daze_dosfs_default_environment(environment, sizeof(environment), &environment_length);
  if (environment_status != DAZE_DOSFS_OK || environment_length != sizeof(expected_environment) ||
      memcmp(environment, expected_environment, sizeof(expected_environment)) != 0) {
    fprintf(stderr, "default environment mismatch\n");
    pass = 0;
  }

  char temporary_root[64];
  const char *host_tmp_directory = getenv("TMPDIR");
  if (host_tmp_directory == NULL) host_tmp_directory = "/tmp";
  const int root_length = snprintf(temporary_root, sizeof(temporary_root),
                                   "%s/daze-dosfs-contract-XXXXXX", host_tmp_directory);
  if (root_length < 0 || (size_t)root_length >= sizeof(temporary_root)) return 1;
  char source_directory[64];
  if (mkdtemp(temporary_root) == NULL ||
      snprintf(source_directory, sizeof(source_directory), "%s/SRC", temporary_root) < 0 ||
      mkdir(source_directory, 0700) != 0) {
    fprintf(stderr, "cannot set up host filesystem contract test\n");
    return 1;
  }
  int root_fd = open(temporary_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  int c_drive = -1;
  if (root_fd < 0 ||
      daze_dosfs_mounts_add_default(&mounts, root_fd, 0, &c_drive) != DAZE_DOSFS_OK ||
      c_drive != 2) {
    fprintf(stderr, "cannot register C: mount\n");
    return 1;
  }
  pass &= mount_rejections_contract(root_fd);
  char source_path[128];
  snprintf(source_path, sizeof(source_path), "%s/MIPS.S", source_directory);
  int source_fd = open(source_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (source_fd < 0 || write(source_fd, "ok", 2) != 2 || close(source_fd) != 0) {
    fprintf(stderr, "cannot prepare source file\n");
    return 1;
  }
  int guest_fd = -1;
  int host_errno = 0;
  if (daze_dosfs_ensure_temp_directory(&mounts, &host_errno) != DAZE_DOSFS_OK ||
      daze_dosfs_ensure_temp_directory(&mounts, &host_errno) != DAZE_DOSFS_OK) {
    fprintf(stderr, "C:\\TMP setup failed: %d\n", host_errno);
    return 1;
  }
  if (daze_dosfs_open_c(&mounts, "c:\\src\\mips.s", O_RDONLY, 0, &guest_fd, &host_errno) !=
        DAZE_DOSFS_OK ||
      read(guest_fd, environment, 2) != 2 || memcmp(environment, "ok", 2) != 0) {
    fprintf(stderr, "descriptor-relative guest open failed: %d\n", host_errno);
    pass = 0;
  }
  close(guest_fd);
  char link_path[128];
  snprintf(link_path, sizeof(link_path), "%s/LINK", temporary_root);
  if (symlink("/etc", link_path) != 0 ||
      daze_dosfs_open_c(&mounts, "C:\\LINK\\passwd", O_RDONLY, 0, &guest_fd, &host_errno) !=
        DAZE_DOSFS_HOST_ERROR) {
    fprintf(stderr, "symlink escape was not rejected\n");
    pass = 0;
  }
  /* A second mount becomes D: and is reachable only through its drive letter. */
  int d_fd = open(temporary_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (d_fd < 0) {
    fprintf(stderr, "cannot open second mount root\n");
    return 1;
  }
  char d_source_path[128];
  snprintf(d_source_path, sizeof(d_source_path), "%s/DATA.BIN", temporary_root);
  int d_source_fd = open(d_source_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (d_source_fd < 0 || write(d_source_fd, "dy", 2) != 2 || close(d_source_fd) != 0) {
    fprintf(stderr, "cannot prepare D: mount file\n");
    return 1;
  }
  const int case_files_ready =
    create_file_at(root_fd, "Case.TXT") && create_file_at(root_fd, "CASE.TXT") &&
    create_file_at(root_fd, "A-VERY-LONG-FILENAME.TXT") &&
    symlinkat("missing-target", root_fd, "BROKEN") == 0 && mkfifoat(root_fd, "PIPE", 0600) == 0;
  if (!case_files_ready) {
    fprintf(stderr, "cannot prepare DOS directory-enumeration entries\n");
    return 1;
  }
  pass &= find_listing_contract(&mounts);
  int case_fd = -1;
  pass &=
    daze_dosfs_open_c(&mounts, "C:\\Case.TXT", O_RDONLY, 0, &case_fd, &host_errno) == DAZE_DOSFS_OK;
  if (case_fd >= 0) close(case_fd);
  case_fd = -1;
  host_errno = 0;
  pass &= daze_dosfs_open_c(&mounts, "C:\\case.txt", O_RDONLY, 0, &case_fd, &host_errno) ==
            DAZE_DOSFS_HOST_ERROR &&
          host_errno == EEXIST;
  if (case_fd >= 0) close(case_fd);

  int d_drive = -1;
  if (daze_dosfs_mounts_add_default(&mounts, d_fd, 0, &d_drive) != DAZE_DOSFS_OK || d_drive != 3) {
    fprintf(stderr, "D: mount was not registered as drive 3\n");
    pass = 0;
  }
  if (daze_dosfs_open_c(&mounts, "d:\\DATA.BIN", O_RDONLY, 0, &guest_fd, &host_errno) !=
        DAZE_DOSFS_OK ||
      read(guest_fd, environment, 2) != 2 || memcmp(environment, "dy", 2) != 0) {
    fprintf(stderr, "D: mount open failed: %d\n", host_errno);
    pass = 0;
  }
  if (guest_fd >= 0) close(guest_fd);
  /* A mount can also be pinned to an explicit drive letter (A:=0, ..., Z:=25). */
  int x_fd = open(temporary_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int duplicate_fd = open(temporary_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (x_fd < 0 || duplicate_fd < 0 ||
      daze_dosfs_mounts_add_named(&mounts, 'X' - 'A', x_fd, 0) != DAZE_DOSFS_OK) {
    fprintf(stderr, "named X: mount was not registered at drive 23\n");
    pass = 0;
  }
  if (daze_dosfs_open_c(&mounts, "x:\\DATA.BIN", O_RDONLY, 0, &guest_fd, &host_errno) !=
        DAZE_DOSFS_OK ||
      read(guest_fd, environment, 2) != 2 || memcmp(environment, "dy", 2) != 0) {
    fprintf(stderr, "named X: mount open failed: %d\n", host_errno);
    pass = 0;
  }
  if (guest_fd >= 0) close(guest_fd);
  if (daze_dosfs_mounts_add_named(&mounts, 'D' - 'A', duplicate_fd, 0) != DAZE_DOSFS_DRIVE_IN_USE) {
    fprintf(stderr, "a duplicate D: mount was not rejected\n");
    pass = 0;
  }
  if (duplicate_fd >= 0) close(duplicate_fd);
  if (daze_dosfs_open_c(&mounts, "E:\\DATA.BIN", O_RDONLY, 0, &guest_fd, &host_errno) !=
      DAZE_DOSFS_UNMOUNTED_DRIVE) {
    fprintf(stderr, "unmounted E: drive was not rejected\n");
    pass = 0;
  }
  /* A readonly mount serves reads while write-mode opens, creates, and
   * deletes fail as host EROFS (DOS access denied). */
  int r_fd = open(temporary_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (r_fd < 0 || daze_dosfs_mounts_add_named(&mounts, 'R' - 'A', r_fd, 1) != DAZE_DOSFS_OK) {
    fprintf(stderr, "named R: readonly mount was not registered\n");
    pass = 0;
  }
  if (!daze_dosfs_mount_is_readonly(&mounts, 'R' - 'A') ||
      daze_dosfs_mount_is_readonly(&mounts, 'C' - 'A')) {
    fprintf(stderr, "readonly mount flag mismatch\n");
    pass = 0;
  }
  if (daze_dosfs_open_c(&mounts, "r:\\DATA.BIN", O_RDONLY, 0, &guest_fd, &host_errno) !=
        DAZE_DOSFS_OK ||
      read(guest_fd, environment, 2) != 2 || memcmp(environment, "dy", 2) != 0) {
    fprintf(stderr, "readonly R: mount read failed: %d\n", host_errno);
    pass = 0;
  }
  if (guest_fd >= 0) close(guest_fd);
  guest_fd = -1;
  if (daze_dosfs_open_c(&mounts, "r:\\DATA.BIN", O_RDWR, 0, &guest_fd, &host_errno) !=
        DAZE_DOSFS_HOST_ERROR ||
      host_errno != EROFS) {
    fprintf(stderr, "readonly R: mount write-mode open was not rejected\n");
    pass = 0;
  }
  if (daze_dosfs_open_c(&mounts, "r:\\NEWFILE.BIN", O_WRONLY | O_CREAT | O_TRUNC, 0600, &guest_fd,
                        &host_errno) != DAZE_DOSFS_HOST_ERROR ||
      host_errno != EROFS) {
    fprintf(stderr, "readonly R: mount create was not rejected\n");
    pass = 0;
  }
  if (daze_dosfs_unlink_c(&mounts, "r:\\DATA.BIN", &host_errno) != DAZE_DOSFS_HOST_ERROR ||
      host_errno != EROFS) {
    fprintf(stderr, "readonly R: mount delete was not rejected\n");
    pass = 0;
  }
  /* A readonly default drive refuses C:\TMP setup so the runner can skip it
   * and let later guest temp-file creation fail with access denied. */
  DazeDosfsMounts ro_mounts;
  daze_dosfs_mounts_init(&ro_mounts);
  int ro_fd = open(temporary_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int ro_drive = -1;
  int ro_errno = 0;
  if (ro_fd < 0 ||
      daze_dosfs_mounts_add_default(&ro_mounts, ro_fd, 1, &ro_drive) != DAZE_DOSFS_OK ||
      ro_drive != 2 || !daze_dosfs_mount_is_readonly(&ro_mounts, 2) ||
      daze_dosfs_ensure_temp_directory(&ro_mounts, &ro_errno) != DAZE_DOSFS_HOST_ERROR ||
      ro_errno != EROFS) {
    fprintf(stderr, "readonly C: mount TMP setup was not rejected\n");
    pass = 0;
  }
  close(ro_fd);
  DazeDosfsHandles service_handles;
  daze_dosfs_handles_init(&service_handles);
  if (daze_dosfs_handles_bind_standard(&service_handles, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                                       &host_errno) != DAZE_DOSFS_OK) {
    fprintf(stderr, "cannot bind file-service handles: %d\n", host_errno);
    return 1;
  }
  DazeDosfsFileService file_service;
  daze_dosfs_file_service_init(&file_service, &mounts, &service_handles);
  DazeDosfsFileResult file_result = {0};
  daze_dosfs_file_open(&file_service, "C:\\SRC\\MIPS.S", 0, &file_result);
  if (!file_result.success || file_result.handle != 5) {
    fprintf(stderr, "file service open mismatch: success=%d handle=%u error=%u\n",
            file_result.success, file_result.handle, file_result.dos_error);
    pass = 0;
  }
  const uint16_t service_handle = file_result.handle;
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_read(&file_service, service_handle, 3, &file_result);
  if (!file_result.success || file_result.byte_count != 2 ||
      memcmp(file_result.bytes, "ok", 2) != 0) {
    fprintf(stderr, "file service short-read mismatch\n");
    pass = 0;
  }
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_seek(&file_service, service_handle, 0, 0, &file_result);
  if (!file_result.success || file_result.position != 0) {
    fprintf(stderr, "file service seek mismatch\n");
    pass = 0;
  }
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_seek(&file_service, service_handle, 3, 0, &file_result);
  if (file_result.success || file_result.dos_error != 6) {
    fprintf(stderr, "file service invalid-origin mismatch\n");
    pass = 0;
  }
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_read(&file_service, 255, 1, &file_result);
  if (file_result.success || file_result.dos_error != 6) {
    fprintf(stderr, "file service invalid-handle mismatch\n");
    pass = 0;
  }
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_open(&file_service, "C:\\MISSING.EXE", 0, &file_result);
  if (file_result.success || file_result.dos_error != 2) {
    fprintf(stderr, "file service missing-path mismatch\n");
    pass = 0;
  }
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_open(&file_service, "C:\\SRC\\MIPS.S", 0x40, &file_result);
  if (!file_result.success || file_result.handle != 6) {
    fprintf(stderr, "file service shared read-only open mismatch\n");
    pass = 0;
  }
  const uint16_t shared_service_handle = file_result.handle;
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_open(&file_service, "C:\\SRC\\MIPS.S", 0x80, &file_result);
  if (!file_result.success || file_result.handle != 7) {
    fprintf(stderr, "file service no-inherit read-only open mismatch\n");
    pass = 0;
  }
  const uint16_t noinherit_service_handle = file_result.handle;
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_open(&file_service, "C:\\SRC\\MIPS.S", 3, &file_result);
  if (file_result.success || file_result.dos_error != 12) {
    fprintf(stderr, "file service access-mode mismatch\n");
    pass = 0;
  }
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_create(&file_service, "R:\\NEWFILE.BIN", &file_result);
  if (file_result.success || file_result.dos_error != 5) {
    fprintf(stderr, "file service readonly create mismatch\n");
    pass = 0;
  }
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_open(&file_service, "R:\\DATA.BIN", 1, &file_result);
  if (file_result.success || file_result.dos_error != 5) {
    fprintf(stderr, "file service readonly write-open mismatch\n");
    pass = 0;
  }
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_open(&file_service, "R:\\DATA.BIN", 2, &file_result);
  if (file_result.success || file_result.dos_error != 5) {
    fprintf(stderr, "file service readonly read-write-open mismatch\n");
    pass = 0;
  }
  daze_dosfs_file_result_dispose(&file_result);
  daze_dosfs_file_open(&file_service, "R:\\DATA.BIN", 0, &file_result);
  if (!file_result.success) {
    fprintf(stderr, "file service readonly read-open mismatch\n");
    pass = 0;
  }
  const uint16_t readonly_service_handle = file_result.handle;
  const int readonly_opened = file_result.success;
  daze_dosfs_file_result_dispose(&file_result);
  if (readonly_opened && daze_dosfs_handles_close(&service_handles, readonly_service_handle,
                                                  &host_errno) != DAZE_DOSFS_OK) {
    fprintf(stderr, "file service readonly-handle cleanup failed: %d\n", host_errno);
    pass = 0;
  }
  if (daze_dosfs_handles_close(&service_handles, shared_service_handle, &host_errno) !=
      DAZE_DOSFS_OK) {
    fprintf(stderr, "file service shared-handle cleanup failed: %d\n", host_errno);
    pass = 0;
  }
  if (daze_dosfs_handles_close(&service_handles, noinherit_service_handle, &host_errno) !=
      DAZE_DOSFS_OK) {
    fprintf(stderr, "file service no-inherit-handle cleanup failed: %d\n", host_errno);
    pass = 0;
  }
  if (daze_dosfs_handles_close(&service_handles, service_handle, &host_errno) != DAZE_DOSFS_OK) {
    fprintf(stderr, "file service handle cleanup failed: %d\n", host_errno);
    pass = 0;
  }
  daze_dosfs_handles_close_all(&service_handles);
  close(r_fd);
  close(x_fd);
  close(d_fd);
  unlinkat(root_fd, "Case.TXT", 0);
  unlinkat(root_fd, "CASE.TXT", 0);
  unlinkat(root_fd, "A-VERY-LONG-FILENAME.TXT", 0);
  unlinkat(root_fd, "BROKEN", 0);
  unlinkat(root_fd, "PIPE", 0);
  close(root_fd);
  if (daze_dosfs_errno_to_dos_error(ENOENT) != 2 || daze_dosfs_errno_to_dos_error(ENOTDIR) != 3 ||
      daze_dosfs_errno_to_dos_error(EACCES) != 5 || daze_dosfs_errno_to_dos_error(EROFS) != 5 ||
      daze_dosfs_errno_to_dos_error(EPERM) != 5 || daze_dosfs_errno_to_dos_error(EMFILE) != 4 ||
      daze_dosfs_errno_to_dos_error(ENFILE) != 4 || daze_dosfs_errno_to_dos_error(EEXIST) != 80 ||
      daze_dosfs_errno_to_dos_error(ENOSPC) != 112 || daze_dosfs_errno_to_dos_error(EINVAL) != 87 ||
      daze_dosfs_errno_to_dos_error(EIO) != 1 ||
      strcmp(daze_dosfs_status_string(DAZE_DOSFS_OK), "ok") != 0 ||
      strcmp(daze_dosfs_status_string(DAZE_DOSFS_INVALID_PATH), "invalid DOS path") != 0 ||
      strcmp(daze_dosfs_status_string(DAZE_DOSFS_UNMOUNTED_DRIVE), "DOS drive is not mounted") !=
        0 ||
      strcmp(daze_dosfs_status_string(DAZE_DOSFS_DRIVE_IN_USE), "DOS drive is already mounted") !=
        0 ||
      strcmp(daze_dosfs_status_string(DAZE_DOSFS_OUTPUT_TOO_SMALL), "output buffer is too small") !=
        0 ||
      strcmp(daze_dosfs_status_string(DAZE_DOSFS_HOST_ERROR), "host filesystem error") != 0 ||
      strcmp(daze_dosfs_status_string((DazeDosfsStatus)99), "unknown DOS filesystem status") != 0) {
    fprintf(stderr, "POSIX-to-DOS error mapping mismatch\n");
    pass = 0;
  }
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  if (daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                                       &host_errno) != DAZE_DOSFS_OK) {
    fprintf(stderr, "cannot bind standard DOS handles: %d\n", host_errno);
    return 1;
  }
  guest_fd = open(source_path, O_RDONLY | O_CLOEXEC);
  uint16_t dos_handle = 0;
  int table_fd = -1;
  if (guest_fd < 0 || daze_dosfs_handles_adopt(&handles, guest_fd, &dos_handle) != DAZE_DOSFS_OK ||
      dos_handle != 5 || daze_dosfs_handles_get(&handles, dos_handle, &table_fd) != DAZE_DOSFS_OK ||
      table_fd != guest_fd ||
      daze_dosfs_handles_close(&handles, dos_handle, &host_errno) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_get(&handles, dos_handle, &table_fd) != DAZE_DOSFS_INVALID_PATH) {
    fprintf(stderr, "DOS handle-table ownership mismatch\n");
    pass = 0;
  }
  guest_fd = open(source_path, O_RDONLY | O_CLOEXEC);
  uint16_t duplicate_handle = 0;
  char first_byte = '\0';
  char second_byte = '\0';
  if (guest_fd < 0 || daze_dosfs_handles_adopt(&handles, guest_fd, &dos_handle) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_duplicate(&handles, dos_handle, &duplicate_handle, &host_errno) !=
        DAZE_DOSFS_OK ||
      duplicate_handle == dos_handle ||
      daze_dosfs_handles_get(&handles, duplicate_handle, &table_fd) != DAZE_DOSFS_OK ||
      read(guest_fd, &first_byte, 1) != 1 || read(table_fd, &second_byte, 1) != 1 ||
      first_byte != 'o' || second_byte != 'k' ||
      daze_dosfs_handles_close(&handles, dos_handle, &host_errno) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_get(&handles, duplicate_handle, &table_fd) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_close(&handles, duplicate_handle, &host_errno) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_duplicate(&handles, dos_handle, &duplicate_handle, &host_errno) !=
        DAZE_DOSFS_INVALID_PATH) {
    fprintf(stderr, "DOS handle duplication mismatch\n");
    pass = 0;
  }
  guest_fd = open(source_path, O_RDONLY | O_CLOEXEC);
  DazeDosfsHandles inherited;
  daze_dosfs_handles_init(&inherited);
  int inherited_fd = -1;
  int parent_stdout = -1;
  if (guest_fd < 0 || daze_dosfs_handles_adopt(&handles, guest_fd, &dos_handle) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_get(&handles, 1, &parent_stdout) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_inherit(&handles, &inherited, &host_errno) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_get(&inherited, dos_handle, &inherited_fd) != DAZE_DOSFS_OK ||
      inherited_fd == guest_fd || read(inherited_fd, &first_byte, 1) != 1 ||
      read(guest_fd, &second_byte, 1) != 1 || first_byte != 'o' || second_byte != 'k' ||
      daze_dosfs_handles_close(&inherited, 1, &host_errno) != DAZE_DOSFS_OK ||
      fcntl(parent_stdout, F_GETFD) == -1 ||
      daze_dosfs_handles_force_duplicate(&inherited, dos_handle, 1, &host_errno) != DAZE_DOSFS_OK ||
      fcntl(parent_stdout, F_GETFD) == -1) {
    fprintf(stderr, "DOS inherited handles must share positions but own independent closes\n");
    pass = 0;
  }
  daze_dosfs_handles_close_all(&inherited);
  if (fcntl(guest_fd, F_GETFD) == -1 || fcntl(parent_stdout, F_GETFD) == -1) pass = 0;
  DazeDosfsHandles invalid_parent = handles;
  invalid_parent.host_fds[DAZE_DOSFS_MAX_HANDLES - 1] = INT_MAX;
  if (daze_dosfs_handles_inherit(&invalid_parent, &inherited, &host_errno) !=
        DAZE_DOSFS_HOST_ERROR ||
      host_errno != EBADF) {
    fprintf(stderr, "DOS handle inheritance failure was not reported\n");
    pass = 0;
  }
  for (size_t index = 0; index < DAZE_DOSFS_MAX_HANDLES; ++index) {
    if (inherited.host_fds[index] != -1) pass = 0;
  }
  if (daze_dosfs_handles_close(&handles, dos_handle, &host_errno) != DAZE_DOSFS_OK) pass = 0;
  guest_fd = open(source_path, O_RDONLY | O_CLOEXEC);
  int replaced_fd = -1;
  if (guest_fd < 0 || daze_dosfs_handles_adopt(&handles, guest_fd, &dos_handle) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_get(&handles, 2, &replaced_fd) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_force_duplicate(&handles, dos_handle, 2, &host_errno) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_get(&handles, 2, &table_fd) != DAZE_DOSFS_OK ||
      fcntl(replaced_fd, F_GETFD) != -1 || errno != EBADF || read(guest_fd, &first_byte, 1) != 1 ||
      read(table_fd, &second_byte, 1) != 1 || first_byte != 'o' || second_byte != 'k' ||
      daze_dosfs_handles_close(&handles, dos_handle, &host_errno) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_close(&handles, 2, &host_errno) != DAZE_DOSFS_OK ||
      daze_dosfs_handles_force_duplicate(&handles, dos_handle, DAZE_DOSFS_MAX_HANDLES,
                                         &host_errno) != DAZE_DOSFS_INVALID_PATH) {
    fprintf(stderr, "DOS forced handle duplication mismatch\n");
    pass = 0;
  }
  daze_dosfs_handles_close_all(&handles);
  unlink(link_path);
  unlink(source_path);
  unlink(d_source_path);
  char temporary_directory[128];
  snprintf(temporary_directory, sizeof(temporary_directory), "%s/TMP", temporary_root);
  rmdir(temporary_directory);
  rmdir(source_directory);
  rmdir(temporary_root);
  fprintf(stderr, "DOS filesystem contract test: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
