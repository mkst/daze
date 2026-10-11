#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "int21_service.h"
#include "dos_error.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      fprintf(stderr, "DOS boundary failed at %d\n", __LINE__);                                    \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

typedef struct {
  uint8_t bytes[512];
  int fail_read, fail_write;
} Memory;

static int read_memory(void *opaque, uint16_t segment, uint16_t offset, void *bytes, size_t size) {
  Memory *memory = opaque;
  if (segment != 0x600 || memory->fail_read || offset > sizeof(memory->bytes) ||
      size > sizeof(memory->bytes) - offset)
    return 0;
  memcpy(bytes, memory->bytes + offset, size);
  return 1;
}

static int write_memory(void *opaque, uint16_t segment, uint16_t offset, const void *bytes,
                        size_t size) {
  Memory *memory = opaque;
  if (segment != 0x600 || memory->fail_write || offset > sizeof(memory->bytes) ||
      size > sizeof(memory->bytes) - offset)
    return 0;
  memcpy(memory->bytes + offset, bytes, size);
  return 1;
}

static DazeDosInt21Result dispatch(const DazeDosInt21Context *context, uint16_t ax,
                                   DazeDosInt21DispatchStatus status) {
  const DazeDosInt21Request request = {.ax = ax,
                                       .bx = 99,
                                       .cx = 8,
                                       .dx = 0,
                                       .ds = 0x600,
                                       .es = 0x600,
                                       .si = 0,
                                       .di = 256,
                                       .flags = 0x246};
  DazeDosInt21Result result;
  memset(&result, 0xa5, sizeof(result));
  CHECK(daze_dos_int21_dispatch(context, &request, &result) == status);
  if (status != DAZE_DOS_INT21_DISPATCH_OK) {
    CHECK(result.register_write_mask == 0 && result.flag_write_mask == 0);
    CHECK(result.disposition ==
          (ax == 0x5800 ? DAZE_DOS_INT21_HANDLED : DAZE_DOS_INT21_UNSUPPORTED));
  }
  return result;
}

static void error_reply(DazeDosInt21Result result, uint16_t ax) {
  CHECK(result.disposition == DAZE_DOS_INT21_HANDLED);
  CHECK(result.register_write_mask == DAZE_DOS_INT21_REG_AX && result.ax == ax);
  CHECK(result.flag_write_mask == DAZE_DOS_INT21_FLAG_CF &&
        result.flag_values == DAZE_DOS_INT21_FLAG_CF);
}

int main(void) {
  char directory[] = "/tmp/daze-int21-boundary-XXXXXX";
  CHECK(mkdtemp(directory) != NULL);
  int mount = open(directory, O_RDONLY | O_DIRECTORY);
  CHECK(mount >= 0);
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  DazeDosProcessState process;
  DazeDosMemory allocator;
  Memory memory = {0};
  daze_dosfs_mounts_init(&mounts);
  mounts.fds[2] = mount;
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  daze_dos_process_state_init(&process, 0x1000);
  daze_dos_process_state_set_dta(&process, 0x600, 128);
  daze_dos_memory_init(&allocator, 0x3000, 0xa000);
  DazeDosInt21Context context = {.files = &files,
                                 .process_state = &process,
                                 .dos_memory = &allocator,
                                 .guest_memory = {&memory, read_memory, write_memory},
                                 .dbcs_table_segment = 0x600,
                                 .sda_segment = 0x600,
                                 .indos_segment = 0x600};
  DazeDosInt21Request request = {.ax = 0x3000};
  DazeDosInt21Result result;
  CHECK(daze_dos_int21_dispatch(&context, &request, NULL) ==
        DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
  CHECK(daze_dos_int21_dispatch(&context, NULL, &result) ==
        DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
  CHECK(result.register_write_mask == 0 && result.flag_write_mask == 0);

  const uint16_t files_required[] = {0x1900, 0x3c00, 0x3d00, 0x3e00, 0x3f00, 0x4000,
                                     0x4100, 0x4200, 0x4300, 0x4400, 0x4600, 0x4700,
                                     0x4e00, 0x5600, 0x5700, 0x5a00};
  for (size_t i = 0; i < sizeof(files_required) / sizeof(files_required[0]); ++i) {
    DazeDosInt21Context missing = context;
    missing.files = NULL;
    DazeDosfsHandles before = handles;
    dispatch(&missing, files_required[i], DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
    CHECK(memcmp(&handles, &before, sizeof(handles)) == 0);
  }
  const uint16_t mounts_required[] = {0x1900, 0x3c00, 0x4100, 0x4300,
                                      0x4700, 0x4e00, 0x5600, 0x5a00};
  files.mounts = NULL;
  for (size_t i = 0; i < sizeof(mounts_required) / sizeof(mounts_required[0]); ++i)
    dispatch(&context, mounts_required[i], DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
  files.mounts = &mounts;
  const uint16_t handles_required[] = {0x3c00, 0x3e00, 0x3f00, 0x4200,
                                       0x4400, 0x4600, 0x5700, 0x5a00};
  files.handles = NULL;
  for (size_t i = 0; i < sizeof(handles_required) / sizeof(handles_required[0]); ++i)
    dispatch(&context, handles_required[i], DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
  files.handles = &handles;
  const uint16_t process_required[] = {0x1a00, 0x2f00, 0x4d00, 0x4e00, 0x4f00,
                                       0x5000, 0x5100, 0x6200, 0x5a00};
  DazeDosInt21Context missing = context;
  missing.process_state = NULL;
  for (size_t i = 0; i < sizeof(process_required) / sizeof(process_required[0]); ++i)
    dispatch(&missing, process_required[i], DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
  dispatch(&missing, 0x5800, DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
  missing = context;
  missing.dos_memory = NULL;
  dispatch(&missing, 0x4800, DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);

  memcpy(memory.bytes, "MISSING.TXT", 12);
  missing = context;
  missing.guest_memory.read = NULL;
  const uint16_t path_reads[] = {0x3c00, 0x4100, 0x4300, 0x4e00, 0x5600};
  for (size_t i = 0; i < sizeof(path_reads) / sizeof(path_reads[0]); ++i)
    dispatch(&missing, path_reads[i], DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
  dispatch(&missing, 0x5a00, DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
  missing = context;
  missing.guest_memory.write = NULL;
  dispatch(&missing, 0x5a00, DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
  const uint16_t tables[] = {0x3400, 0x3800, 0x6300, 0x5d06};
  for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); ++i) {
    Memory before = memory;
    dispatch(&missing, tables[i], DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE);
    CHECK(memcmp(&memory, &before, sizeof(memory)) == 0);
  }
  memory.fail_read = 1;
  for (size_t i = 0; i < sizeof(path_reads) / sizeof(path_reads[0]); ++i)
    dispatch(&context, path_reads[i], DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE);
  dispatch(&context, 0x5a00, DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE);
  dispatch(&context, 0x2900, DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE);
  memory.fail_read = 0;
  memory.fail_write = 1;
  for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); ++i)
    dispatch(&context, tables[i], DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE);
  dispatch(&context, 0x2900, DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE);
  memory.fail_write = 0;
  memcpy(memory.bytes, "1:FILE.TXT", 11);
  Memory before = memory;
  result = dispatch(&context, 0x2900, DAZE_DOS_INT21_DISPATCH_OK);
  CHECK(result.ax == 0x29ff && result.register_write_mask == DAZE_DOS_INT21_REG_AX);
  CHECK(memcmp(&memory, &before, sizeof(memory)) == 0);
  memset(memory.bytes, 'X', 128);
  dispatch(&context, 0x2900, DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE);
  memcpy(memory.bytes, "FILE.TXT\r", 10);
  result = dispatch(&context, 0x2900, DAZE_DOS_INT21_DISPATCH_OK);
  CHECK(result.si == 8 && result.ax == 0x2900 &&
        memcmp(memory.bytes + 257, "FILE    TXT", 11) == 0);
  memcpy(memory.bytes, "FILE.TXT ", 10);
  result = dispatch(&context, 0x2900, DAZE_DOS_INT21_DISPATCH_OK);
  CHECK(result.si == 8 && result.ax == 0x2900);

  const char *bad_paths[] = {"Z:\\MISSING.TXT", "MISSING.TXT"};
  for (size_t i = 0; i < 2; ++i) {
    strcpy((char *)memory.bytes, bad_paths[i]);
    error_reply(dispatch(&context, 0x4100, DAZE_DOS_INT21_DISPATCH_OK), i == 0 ? 3 : 2);
    error_reply(dispatch(&context, 0x4e00, DAZE_DOS_INT21_DISPATCH_OK), i == 0 ? 3 : 18);
  }
  const char *names[] = {"ONE.TXT", "TWO.TXT", "KEEP.BIN"};
  for (size_t i = 0; i < 3; ++i) {
    int fd = openat(mount, names[i], O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "contents", 8) == 8);
    close(fd);
  }
  strcpy((char *)memory.bytes, "*.TXT");
  result = dispatch(&context, 0x4e00, DAZE_DOS_INT21_DISPATCH_OK);
  CHECK(result.flag_values == 0 && result.register_write_mask == 0);
  char first[13];
  memcpy(first, memory.bytes + 128 + 0x1e, 13);
  result = dispatch(&context, 0x4f00, DAZE_DOS_INT21_DISPATCH_OK);
  CHECK(result.flag_values == 0 && result.register_write_mask == 0);
  CHECK(strcmp(first, (char *)memory.bytes + 128 + 0x1e) != 0);
  CHECK(strcmp(first, "ONE.TXT") == 0 || strcmp(first, "TWO.TXT") == 0);
  dispatch(&context, 0x4e00, DAZE_DOS_INT21_DISPATCH_OK);
  missing = context;
  missing.guest_memory.write = NULL;
  error_reply(dispatch(&missing, 0x4f00, DAZE_DOS_INT21_DISPATCH_OK), 18);
  error_reply(dispatch(&missing, 0x4e00, DAZE_DOS_INT21_DISPATCH_OK), 18);
  error_reply(dispatch(&context, 0x4600, DAZE_DOS_INT21_DISPATCH_OK), 6);
  handles.host_fds[10] = INT_MAX;
  request = (DazeDosInt21Request){.ax = 0x4600, .bx = 10, .cx = 11};
  CHECK(daze_dos_int21_dispatch(&context, &request, &result) == DAZE_DOS_INT21_DISPATCH_OK);
  error_reply(result, DAZE_DOS_ERR_INVALID_FUNCTION);
  CHECK(handles.host_fds[10] == INT_MAX && handles.host_fds[11] == -1);
  request.ax = 0x3e00;
  CHECK(daze_dos_int21_dispatch(&context, &request, &result) == DAZE_DOS_INT21_DISPATCH_OK);
  error_reply(result, DAZE_DOS_ERR_INVALID_FUNCTION);
  handles.host_fds[10] = -1;
  missing = context;
  missing.guest_memory.write = NULL;
  error_reply(dispatch(&missing, 0x4700, DAZE_DOS_INT21_DISPATCH_OK), 15);
  mounts.default_drive = -1;
  error_reply(dispatch(&context, 0x4700, DAZE_DOS_INT21_DISPATCH_OK), 15);
  mounts.default_drive = 2;
  const uint16_t unsupported[] = {0x6301, 0x5d00, 0x4301, 0x4401};
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i) {
    result = dispatch(&context, unsupported[i], DAZE_DOS_INT21_DISPATCH_OK);
    CHECK(result.disposition == DAZE_DOS_INT21_UNSUPPORTED && result.register_write_mask == 0 &&
          result.flag_write_mask == 0);
  }
  daze_dos_process_state_dispose(&process);
  daze_dosfs_handles_close_all(&handles);
  for (size_t i = 0; i < 3; ++i)
    CHECK(unlinkat(mount, names[i], 0) == 0);
  close(mount);
  CHECK(rmdir(directory) == 0);
  puts("DOS service boundary contract: passed");
  return 0;
}
