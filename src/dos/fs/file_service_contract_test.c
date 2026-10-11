#include "file_service.h"

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void failed(const DazeDosfsFileResult *result, uint16_t error) {
  assert(!result->success && result->dos_error == error && result->byte_count == 0 &&
         result->bytes == NULL && result->transfer_bytes == NULL);
}

int main(void) {
  char directory[] = "/tmp/daze-file-service-XXXXXX";
  assert(mkdtemp(directory));
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  DazeDosfsFileResult result = {0};
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  int root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(root >= 0 && daze_dosfs_mounts_add_named(&mounts, 2, root, 0) == DAZE_DOSFS_OK);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  daze_dosfs_file_open(&files, "C:\\", 0, &result);
  failed(&result, 5);
  daze_dosfs_file_create_exclusive(&files, "DATA.BIN", &result);
  assert(result.success);
  uint16_t handle = result.handle;
  daze_dosfs_file_create_exclusive(&files, "DATA.BIN", &result);
  failed(&result, 80);
  uint8_t bytes[8] = {0};
  daze_dosfs_file_read(&files, handle, 0, &result);
  assert(result.success && !result.host_read_attempted && !result.bytes && !result.byte_count);
  daze_dosfs_file_read_into(&files, handle, NULL, 0, &result);
  assert(result.success && !result.host_read_attempted);
  daze_dosfs_file_write(&files, handle, (const uint8_t *)"abc", 3, &result);
  assert(result.success && result.byte_count == 3 && result.host_write_attempted);
  daze_dosfs_file_seek(&files, handle, 1, -1, &result);
  assert(result.success && result.position == 2);
  daze_dosfs_file_seek(&files, handle, 2, -2, &result);
  assert(result.success && result.position == 1);
  daze_dosfs_file_read_into(&files, handle, bytes, sizeof(bytes), &result);
  assert(result.success && result.byte_count == 2 && memcmp(bytes, "bc", 2) == 0 &&
         result.transfer_bytes == bytes && result.bytes == NULL);
  daze_dosfs_file_result_dispose(&result);
  assert(memcmp(bytes, "bc", 2) == 0);
  daze_dosfs_file_seek(&files, handle, 0, -1, &result);
  failed(&result, 87);
  daze_dosfs_file_seek(&files, handle, 0, 1, &result);
  assert(result.success);
  daze_dosfs_file_write(&files, handle, NULL, 0, &result);
  assert(result.success && !result.host_write_attempted);
  daze_dosfs_file_seek(&files, handle, 2, 0, &result);
  assert(result.success && result.position == 1);
  daze_dosfs_file_open(&files, "DATA.BIN", 0, &result);
  assert(result.success);
  uint16_t readonly = result.handle;
  daze_dosfs_file_write(&files, readonly, NULL, 0, &result);
  failed(&result, 5);
  daze_dosfs_file_write(&files, readonly, bytes, 1, &result);
  failed(&result, 1);
  assert(result.host_write_attempted);
  daze_dosfs_file_open(&files, "DATA.BIN", 1, &result);
  assert(result.success);
  uint16_t writeonly = result.handle;
  daze_dosfs_file_read(&files, writeonly, 1, &result);
  failed(&result, 1);
  assert(result.host_read_attempted);
  daze_dosfs_file_read_into(&files, writeonly, bytes, 1, &result);
  failed(&result, 1);
  assert(result.host_read_attempted);
  int pipe_fds[2];
  assert(pipe(pipe_fds) == 0);
  handles.host_fds[1] = pipe_fds[1];
  int host_errno = 99;
  assert(daze_dosfs_file_write_character(&files, 'Q', &host_errno) == DAZE_DOSFS_OK &&
         host_errno == 0 && read(pipe_fds[0], bytes, 1) == 1 && bytes[0] == 'Q');
  daze_dosfs_file_write(&files, 1, NULL, 0, &result);
  assert(result.success && !result.host_write_attempted);
  daze_dosfs_file_seek(&files, 1, 0, 0, &result);
  failed(&result, 1);
  assert(close(pipe_fds[1]) == 0);
  assert(daze_dosfs_file_write_character(&files, 'Q', &host_errno) == DAZE_DOSFS_HOST_ERROR &&
         host_errno == EBADF);
  daze_dosfs_file_write(&files, 1, NULL, 0, &result);
  failed(&result, 1);
  handles.host_fds[1] = -1;
  assert(close(pipe_fds[0]) == 0);
  assert(daze_dosfs_file_write_character(&files, 'Q', NULL) == DAZE_DOSFS_INVALID_PATH);
  daze_dosfs_file_open(NULL, "DATA.BIN", 0, &result);
  failed(&result, 3);
  daze_dosfs_file_create(NULL, "DATA.BIN", &result);
  failed(&result, 3);
  daze_dosfs_file_seek(NULL, handle, 0, 0, &result);
  failed(&result, 6);
  daze_dosfs_file_read(NULL, handle, 1, &result);
  failed(&result, 6);
  daze_dosfs_file_read_into(&files, handle, NULL, 1, &result);
  failed(&result, 6);
  daze_dosfs_file_write(&files, handle, NULL, 1, &result);
  failed(&result, 6);
  daze_dosfs_file_open(&files, NULL, 0, &result);
  failed(&result, 3);
  daze_dosfs_file_open(&files, "DATA.BIN", 0x04, &result);
  failed(&result, 12);
  daze_dosfs_file_open(NULL, NULL, 0, NULL);
  daze_dosfs_file_create(NULL, NULL, NULL);
  daze_dosfs_file_seek(NULL, 0, 0, 0, NULL);
  daze_dosfs_file_read(NULL, 0, 0, NULL);
  daze_dosfs_file_read_into(NULL, 0, NULL, 0, NULL);
  daze_dosfs_file_write(NULL, 0, NULL, 0, NULL);
  daze_dosfs_handles_close_all(&handles);
  assert(unlinkat(root, "DATA.BIN", 0) == 0 && close(root) == 0 && rmdir(directory) == 0);
  puts("DOS file-service contract: passed");
  return 0;
}
