#define _GNU_SOURCE
#include "file_service.h"
#include "int21_service.h"

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_bytes(DazeDosfsFileService *files, uint16_t handle, const char *bytes,
                        uint16_t count) {
  DazeDosfsFileResult result;
  daze_dosfs_file_write(files, handle, (const uint8_t *)bytes, count, &result);
  assert(result.success && result.byte_count == count);
}

static void shared_handles(DazeDosfsFileService *files) {
  DazeDosfsHandles *handles = files->handles;
  DazeDosfsFileResult result;
  daze_dosfs_file_create(files, "SHARED.BIN", &result);
  assert(result.success);
  const uint16_t original = result.handle;
  int fd = -1, host_errno = 0;
  assert(daze_dosfs_handles_peek(handles, original, &fd) == DAZE_DOSFS_OK);
  assert(handles->write_buffers[original] != NULL);
  write_bytes(files, original, "abc", 3);
  struct stat information;
  assert(fstat(fd, &information) == 0 && information.st_size == 0);
  uint16_t duplicate;
  assert(daze_dosfs_handles_duplicate(handles, original, &duplicate, &host_errno) == DAZE_DOSFS_OK);
  assert(handles->write_buffers[duplicate] == handles->write_buffers[original]);
  write_bytes(files, duplicate, "def", 3);
  DazeDosfsExecHandles scope = {0};
  assert(daze_dosfs_exec_handles_begin(&scope, handles, &host_errno) == DAZE_DOSFS_OK);
  write_bytes(files, original, "ghi", 3);
  daze_dosfs_exec_handles_restore(&scope);
  write_bytes(files, duplicate, "jkl", 3);
  daze_dosfs_file_create(files, "REPLACE.BIN", &result);
  assert(result.success);
  const uint16_t target = result.handle;
  write_bytes(files, target, "old", 3);
  assert(daze_dosfs_handles_force_duplicate(handles, duplicate, target, &host_errno) ==
         DAZE_DOSFS_OK);
  assert(handles->write_buffers[target] == handles->write_buffers[original]);
  assert(daze_dosfs_handles_close(handles, original, &host_errno) == DAZE_DOSFS_OK);
  write_bytes(files, target, "mno", 3);
  daze_dosfs_file_seek(files, duplicate, 0, 0, &result);
  assert(result.success && result.position == 0);
  char bytes[16] = {0};
  daze_dosfs_file_read_into(files, target, (uint8_t *)bytes, sizeof(bytes), &result);
  assert(result.success && result.byte_count == 15 && memcmp(bytes, "abcdefghijklmno", 15) == 0);
  assert(daze_dosfs_handles_close(handles, target, &host_errno) == DAZE_DOSFS_OK);
  assert(daze_dosfs_handles_close(handles, duplicate, &host_errno) == DAZE_DOSFS_OK);
  daze_dosfs_file_open(files, "REPLACE.BIN", 0, &result);
  assert(result.success);
  const uint16_t replaced = result.handle;
  daze_dosfs_file_read_into(files, replaced, (uint8_t *)bytes, sizeof(bytes), &result);
  assert(result.success && result.byte_count == 3 && memcmp(bytes, "old", 3) == 0);
  assert(daze_dosfs_handles_close(handles, replaced, &host_errno) == DAZE_DOSFS_OK);
}

static void independent_handles(DazeDosfsFileService *files) {
  DazeDosfsFileResult result;
  daze_dosfs_file_create(files, "ALIAS.BIN", &result);
  assert(result.success);
  uint16_t writer = result.handle;
  write_bytes(files, writer, "abc", 3);
  daze_dosfs_file_open(files, "ALIAS.BIN", 0, &result);
  assert(result.success);
  uint16_t reader = result.handle;
  write_bytes(files, writer, "def", 3);
  char bytes[8] = {0};
  daze_dosfs_file_read_into(files, reader, (uint8_t *)bytes, sizeof(bytes), &result);
  assert(result.success && result.byte_count == 6 && memcmp(bytes, "abcdef", 6) == 0);
  assert(daze_dosfs_handles_close(files->handles, writer, NULL) == DAZE_DOSFS_OK);
  daze_dosfs_file_open(files, "ALIAS.BIN", 2, &result);
  assert(result.success);
  writer = result.handle;
  assert(files->handles->write_buffers[writer] == NULL);
  write_bytes(files, writer, "xyz", 3);
  daze_dosfs_file_seek(files, reader, 0, 0, &result);
  assert(result.success);
  daze_dosfs_file_read(files, reader, 3, &result);
  assert(result.success && result.byte_count == 3 && memcmp(result.bytes, "xyz", 3) == 0);
  daze_dosfs_file_result_dispose(&result);
  assert(daze_dosfs_handles_close(files->handles, writer, NULL) == DAZE_DOSFS_OK);
  assert(daze_dosfs_handles_close(files->handles, reader, NULL) == DAZE_DOSFS_OK);
}

static void sizes_and_disable(DazeDosfsFileService *files) {
  DazeDosfsFileResult result;
  daze_dosfs_file_create(files, "LARGE.BIN", &result);
  assert(result.success);
  uint16_t handle = result.handle;
  char *bytes = malloc(32768);
  assert(bytes);
  memset(bytes, 'x', 32768);
  write_bytes(files, handle, bytes, 16384);
  write_bytes(files, handle, "a", 1);
  write_bytes(files, handle, bytes, 32768);
  int fd;
  assert(daze_dosfs_handles_get(files->handles, handle, &fd) == DAZE_DOSFS_OK);
  struct stat information;
  assert(fstat(fd, &information) == 0 && information.st_size == 49153);
  assert(daze_dosfs_handles_write(files->handles, handle, NULL, 0) == 0);
  assert(daze_dosfs_handles_write(files->handles, handle, NULL, 1) == -1 && errno == EINVAL);
  assert(daze_dosfs_handles_write(NULL, handle, (const uint8_t *)bytes, 1) == -1 && errno == EBADF);
  free(bytes);
  assert(daze_dosfs_handles_close(files->handles, handle, NULL) == DAZE_DOSFS_OK);
  assert(setenv("DAZE_BUFFERED_WRITES", "0", 1) == 0);
  DazeDosfsHandles immediate;
  daze_dosfs_handles_init(&immediate);
  DazeDosfsFileService other;
  daze_dosfs_file_service_init(&other, files->mounts, &immediate);
  daze_dosfs_file_create(&other, "DIRECT.BIN", &result);
  assert(result.success && immediate.write_buffers[result.handle] == NULL);
  handle = result.handle;
  write_bytes(&other, handle, "now", 3);
  assert(daze_dosfs_handles_peek(&immediate, handle, &fd) == DAZE_DOSFS_OK);
  assert(fstat(fd, &information) == 0 && information.st_size == 3);
  daze_dosfs_handles_close_all(&immediate);
  assert(unsetenv("DAZE_BUFFERED_WRITES") == 0);
}

static void deferred_errors(DazeDosfsFileService *files) {
  struct rlimit saved, limited;
  assert(getrlimit(RLIMIT_FSIZE, &saved) == 0);
  limited = saved;
  limited.rlim_cur = 32;
  void (*saved_signal)(int) = signal(SIGXFSZ, SIG_IGN);
  assert(saved_signal != SIG_ERR);
  DazeDosfsFileResult result;
  daze_dosfs_file_create(files, "LIMIT.BIN", &result);
  assert(result.success);
  uint16_t handle = result.handle, duplicate;
  int host_errno = 0, fd;
  assert(daze_dosfs_handles_duplicate(files->handles, handle, &duplicate, &host_errno) ==
         DAZE_DOSFS_OK);
  assert(setrlimit(RLIMIT_FSIZE, &limited) == 0);
  char bytes[64];
  memset(bytes, 'q', sizeof(bytes));
  write_bytes(files, handle, bytes, sizeof(bytes));
  assert(daze_dosfs_handles_get(files->handles, handle, &fd) == DAZE_DOSFS_HOST_ERROR &&
         errno == EFBIG);
  daze_dosfs_file_seek(files, handle, 0, 0, &result);
  assert(!result.success);
  daze_dosfs_file_read(files, handle, 1, &result);
  assert(!result.success && result.bytes == NULL);
  daze_dosfs_file_read_into(files, handle, (uint8_t *)bytes, 1, &result);
  assert(!result.success);
  daze_dosfs_file_write(files, handle, NULL, 0, &result);
  assert(!result.success);
  daze_dosfs_file_open(files, "LIMIT.BIN", 0, &result);
  assert(!result.success);
  daze_dosfs_file_create(files, "LIMIT.BIN", &result);
  assert(!result.success);
  const DazeDosInt21Context context = {.files = files};
  const DazeDosInt21Request request = {.ax = 0x4300};
  DazeDosInt21Result reply;
  assert(daze_dos_int21_dispatch(&context, &request, &reply) == DAZE_DOS_INT21_DISPATCH_OK);
  assert(reply.ax != 0 && reply.disposition == DAZE_DOS_INT21_HANDLED &&
         reply.register_write_mask == DAZE_DOS_INT21_REG_AX &&
         (reply.flag_values & DAZE_DOS_INT21_FLAG_CF));
  uint16_t failed_handle = 0;
  assert(daze_dosfs_handles_duplicate(files->handles, handle, &failed_handle, &host_errno) ==
           DAZE_DOSFS_HOST_ERROR &&
         host_errno == EFBIG);
  assert(daze_dosfs_handles_duplicate(files->handles, handle, &failed_handle, NULL) ==
         DAZE_DOSFS_HOST_ERROR);
  assert(daze_dosfs_handles_force_duplicate(files->handles, handle, 9, &host_errno) ==
           DAZE_DOSFS_HOST_ERROR &&
         host_errno == EFBIG);
  assert(daze_dosfs_handles_force_duplicate(files->handles, handle, 9, NULL) ==
         DAZE_DOSFS_HOST_ERROR);
  assert(daze_dosfs_handles_flush(files->handles, NULL) == DAZE_DOSFS_HOST_ERROR);
  assert(daze_dosfs_handles_flush(NULL, NULL) == DAZE_DOSFS_INVALID_PATH);
  char *large = calloc(32768, 1);
  assert(large);
  assert(daze_dosfs_handles_write(files->handles, handle, (const uint8_t *)large, 16384) == -1 &&
         errno == EFBIG);
  assert(daze_dosfs_handles_write(files->handles, handle, (const uint8_t *)large, 32768) == -1 &&
         errno == EFBIG);
  free(large);
  int alias_fd = openat(files->mounts->fds[2], "LIMIT.BIN", O_RDONLY);
  assert(alias_fd >= 0 &&
         daze_dosfs_handles_adopt(files->handles, alias_fd, &failed_handle) ==
           DAZE_DOSFS_HOST_ERROR &&
         errno == EFBIG);
  assert(close(alias_fd) == 0);
  assert(daze_dosfs_handles_close(files->handles, handle, &host_errno) == DAZE_DOSFS_HOST_ERROR &&
         host_errno == EFBIG);
  assert(setrlimit(RLIMIT_FSIZE, &saved) == 0);
  assert(daze_dosfs_handles_get(files->handles, duplicate, &fd) == DAZE_DOSFS_OK);
  char actual[64];
  assert(pread(fd, actual, sizeof(actual), 0) == sizeof(actual) &&
         memcmp(bytes, actual, sizeof(bytes)) == 0);
  assert(daze_dosfs_handles_close(files->handles, duplicate, NULL) == DAZE_DOSFS_OK);
  daze_dosfs_file_create(files, "CLEANUP.BIN", &result);
  assert(result.success);
  DazeDosfsExecHandles scope = {0};
  assert(daze_dosfs_exec_handles_begin(&scope, files->handles, &host_errno) == DAZE_DOSFS_OK);
  write_bytes(files, result.handle, bytes, sizeof(bytes));
  assert(setrlimit(RLIMIT_FSIZE, &limited) == 0);
  daze_dosfs_exec_handles_restore(&scope);
  assert(files->handles->teardown_errno == EFBIG);
  assert(setrlimit(RLIMIT_FSIZE, &saved) == 0);
  assert(signal(SIGXFSZ, saved_signal) != SIG_ERR);
  daze_dosfs_handles_close_all(files->handles);
}

int main(void) {
  assert(unsetenv("DAZE_BUFFERED_WRITES") == 0);
  char directory[] = "/tmp/daze-write-buffer-XXXXXX";
  assert(mkdtemp(directory));
  int root = open(directory, O_RDONLY | O_DIRECTORY);
  assert(root >= 0);
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  assert(daze_dosfs_mounts_add_named(&mounts, 2, root, 0) == DAZE_DOSFS_OK);
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  DazeDosfsFileService files;
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  shared_handles(&files);
  independent_handles(&files);
  sizes_and_disable(&files);
  deferred_errors(&files);
  const char *paths[] = {"SHARED.BIN", "REPLACE.BIN", "ALIAS.BIN",  "LARGE.BIN",
                         "DIRECT.BIN", "LIMIT.BIN",   "CLEANUP.BIN"};
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
    assert(unlinkat(root, paths[i], 0) == 0);
  assert(close(root) == 0 && rmdir(directory) == 0);
  return 0;
}
