#define _GNU_SOURCE

#include "int21_service.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
  uint8_t bytes[65536];
  int fail_read;
  int fail_write;
  uint16_t segment;
  uint16_t offset;
  size_t size;
} Memory;

typedef struct {
  int calls;
  int succeed;
} PreRelease;

typedef struct {
  int observed;
  int completed;
  uint16_t last_byte_count;
} TransferHooks;

static int pre_release(void *context, uint16_t allocation_segment) {
  PreRelease *hook = context;
  (void)allocation_segment;
  if (hook == NULL) return 0;
  ++hook->calls;
  return hook->succeed;
}

static int memory_read(void *context, uint16_t segment, uint16_t offset, void *bytes, size_t size) {
  Memory *memory = context;
  const size_t position = (size_t)offset + (segment == 0x0601 ? 16 : 0);
  if (memory == NULL || memory->fail_read || (segment != 0x0600 && segment != 0x0601) ||
      position > sizeof(memory->bytes) || size > sizeof(memory->bytes) - position)
    return 0;
  memcpy(bytes, memory->bytes + position, size);
  return 1;
}

static void observe_transfer(void *context, const DazeDosInt21Request *request,
                             const DazeDosfsFileResult *file) {
  TransferHooks *hooks = context;
  (void)request;
  if (hooks == NULL || file == NULL) return;
  ++hooks->observed;
  hooks->last_byte_count = file->byte_count;
}

static void complete_transfer(void *context, const DazeDosInt21Request *request,
                              const DazeDosfsFileResult *file) {
  TransferHooks *hooks = context;
  (void)request;
  if (hooks == NULL || file == NULL) return;
  ++hooks->completed;
  hooks->last_byte_count = file->byte_count;
}

static int memory_write(void *context, uint16_t segment, uint16_t offset, const void *bytes,
                        size_t size) {
  Memory *memory = context;
  if (memory == NULL || memory->fail_write || segment != 0x0600 ||
      size > sizeof(memory->bytes) - offset)
    return 0;
  memcpy(memory->bytes + offset, bytes, size);
  memory->segment = segment;
  memory->offset = offset;
  memory->size = size;
  return 1;
}

static int expect_result(const char *name, DazeDosInt21DispatchStatus actual_status,
                         DazeDosInt21DispatchStatus expected_status,
                         const DazeDosInt21Result *result,
                         DazeDosInt21Disposition expected_disposition, uint16_t register_mask,
                         uint16_t flag_mask, uint16_t flag_values) {
  if (actual_status == expected_status && result->disposition == expected_disposition &&
      result->register_write_mask == register_mask && result->flag_write_mask == flag_mask &&
      result->flag_values == flag_values)
    return 1;
  fprintf(
    stderr,
    "%s: status=%d disposition=%d registers=%04x flags=%04x/%04x expected=%d/%d/%04x/%04x/%04x\n",
    name, actual_status, result->disposition, result->register_write_mask, result->flag_write_mask,
    result->flag_values, expected_status, expected_disposition, register_mask, flag_mask,
    flag_values);
  return 0;
}

static int display_string_contract(void) {
  FILE *output = tmpfile();
  if (output == NULL) return 0;
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  if (daze_dosfs_handles_bind_standard(&handles, 0, fileno(output), 2, NULL) != DAZE_DOSFS_OK) {
    fclose(output);
    return 0;
  }
  DazeDosfsFileService files = {.handles = &handles};
  Memory memory = {0};
  const DazeDosInt21Context context = {
    .files = &files,
    .guest_memory = {.context = &memory, .read = memory_read},
  };
  DazeDosInt21Request request = {.ax = 0x0901, .ds = 0x0600, .dx = 2, .flags = 0x0203};
  DazeDosInt21Result result;
  memcpy(memory.bytes + 2, "hello!$ignored", 14);
  int pass = expect_result("display string", daze_dos_int21_dispatch(&context, &request, &result),
                           DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                           DAZE_DOS_INT21_FLAG_CF, 0);
  rewind(output);
  char actual[16] = {0};
  pass &= fread(actual, 1, sizeof(actual), output) == 6 && strcmp(actual, "hello!") == 0;
  fseek(output, 2, SEEK_SET);
  memory.bytes[2] = '$';
  pass &= expect_result(
    "empty display string", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);
  pass &= ftell(output) == 2;
  fseek(output, 0, SEEK_END);
  pass &= ftell(output) == 6;
  memory.fail_read = 1;
  pass &=
    expect_result("display memory failure", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  pass &= result.ax == 6;
  memory.fail_read = 0;
  memset(memory.bytes + 2, 'x', 4096);
  pass &=
    expect_result("unterminated display", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  pass &= result.ax == 6;
  request.dx = 0xffff;
  memory.bytes[0xffff] = 'x';
  pass &=
    expect_result("display offset overflow", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  pass &= result.ax == 6;
  fseek(output, 0, SEEK_END);
  pass &= ftell(output) == 6;
  request.dx = 2;
  memory.bytes[2 + 4095] = '$';
  pass &= expect_result(
    "maximum display string", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);
  fseek(output, 0, SEEK_END);
  pass &= ftell(output) == 6 + 4095;
  daze_dosfs_handles_close(&handles, 1, NULL);
  memory.bytes[2] = '$';
  pass &=
    expect_result("display invalid stdout", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  pass &= result.ax == 6;
  daze_dosfs_handles_close_all(&handles);
  fclose(output);
  if (!pass) fputs("display string output/preservation contract failed\n", stderr);
  return pass;
}

static int rename_contract(void) {
  char root[] = "/tmp/daze-rename-contract-XXXXXX";
  if (mkdtemp(root) == NULL) return 0;
  const int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (root_fd < 0) return 0;
  int source_fd = openat(root_fd, "Source.O", O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (source_fd < 0) return 0;
  int pass = write(source_fd, "object", 6) == 6;
  close(source_fd);
  pass &= mkdirat(root_fd, "Sub", 0700) == 0;
  pass &= symlinkat("/tmp", root_fd, "LINK") == 0;
  pass &= symlinkat("Source.O", root_fd, "SYM") == 0;
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  mounts.fds[2] = root_fd;
  mounts.fds[3] = root_fd;
  DazeDosfsFileService files = {.mounts = &mounts};
  Memory memory = {0};
  const DazeDosInt21Context context = {.files = &files,
                                       .guest_memory = {.context = &memory, .read = memory_read}};
  DazeDosInt21Request request = {
    .ax = 0x5602, .ds = 0x0600, .dx = 0x20, .es = 0x0601, .di = 0x80, .flags = 0x0203};
  DazeDosInt21Result result;
  memcpy(memory.bytes + 0x20, "c:\\source.o", 12);
  strcpy((char *)memory.bytes + 0x90, "C:\\sub\\Renamed.O");
  pass &= expect_result(
    "rename DS:DX to ES:DI", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);
  source_fd = openat(root_fd, "Sub/Renamed.O", O_RDONLY | O_NOFOLLOW);
  char contents[6];
  pass &= source_fd >= 0 && read(source_fd, contents, sizeof(contents)) == sizeof(contents) &&
          memcmp(contents, "object", sizeof(contents)) == 0 &&
          faccessat(root_fd, "Source.O", F_OK, 0) != 0;
  if (source_fd >= 0) close(source_fd);

  const struct {
    const char *name;
    const char *source;
    const char *destination;
    int readonly;
    uint16_t error;
  } failures[] = {
    {"rename existing case-folded destination", "Sub/Renamed.O", "sub/renamed.o", 0, 5},
    {"rename missing source", "MISSING.O", "OTHER.O", 0, 2},
    {"rename across logical drives", "C:/Sub/Renamed.O", "D:/OTHER.O", 0, 17},
    {"rename readonly mount", "Sub/Renamed.O", "OTHER.O", 1, 5},
    {"rename source through symlink", "LINK/MISSING.O", "OTHER.O", 0, 3},
    {"rename destination through symlink", "Sub/Renamed.O", "LINK/OTHER.O", 0, 3},
    {"rename symlink leaf", "SYM", "OTHER.O", 0, 5},
    {"rename existing symlink destination", "Sub/Renamed.O", "SYM", 0, 5},
    {"rename parent traversal stays at drive root", "Sub/Renamed.O", "../SYM", 0, 5},
  };
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
    strcpy((char *)memory.bytes + 0x20, failures[i].source);
    strcpy((char *)memory.bytes + 0x90, failures[i].destination);
    mounts.readonly[2] = failures[i].readonly;
    pass &= expect_result(failures[i].name, daze_dos_int21_dispatch(&context, &request, &result),
                          DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                          DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
    if (result.ax != failures[i].error) {
      fprintf(stderr, "%s: DOS error %u, expected %u\n", failures[i].name, result.ax,
              failures[i].error);
      pass = 0;
    }
  }
  mounts.readonly[2] = 0;
  strcpy((char *)memory.bytes + 0x20, "Sub/Renamed.O");
  request.es = 0x0602;
  pass &= expect_result(
    "rename inaccessible destination string", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE, &result, DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);
  pass &= faccessat(root_fd, "Sub/Renamed.O", F_OK, 0) == 0 &&
          faccessat(root_fd, "OTHER.O", F_OK, 0) != 0;
  unlinkat(root_fd, "Sub/Renamed.O", 0);
  unlinkat(root_fd, "Source.O", 0);
  unlinkat(root_fd, "LINK", 0);
  unlinkat(root_fd, "SYM", 0);
  unlinkat(root_fd, "Sub", AT_REMOVEDIR);
  close(root_fd);
  rmdir(root);
  return pass;
}

int main(void) {
  int pass = 1;
  Memory memory = {0};
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  DazeDosfsTransferStorage transfer_storage = {0};
  DazeRunMetrics run_metrics = {.enabled = 1};
  DazeDosProcessState process_state;
  DazeDosMemory dos_memory;
  TransferHooks transfer_hooks = {0};
  daze_dosfs_mounts_init(&mounts);
  char mount_template[] = "/tmp/daze-int21-service-XXXXXX";
  if (mkdtemp(mount_template) == NULL) return 1;
  char mount_file[160];
  snprintf(mount_file, sizeof(mount_file), "%s/FILE.TXT", mount_template);
  const int mount_file_fd = open(mount_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (mount_file_fd < 0) return 1;
  if (write(mount_file_fd, "data", 4) != 4) return 1;
  close(mount_file_fd);
  char delete_file[160];
  snprintf(delete_file, sizeof(delete_file), "%s/DELETE.TXT", mount_template);
  const int delete_file_fd = open(delete_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (delete_file_fd < 0) return 1;
  close(delete_file_fd);
  const int mount_fd = open(mount_template, O_RDONLY | O_DIRECTORY);
  if (mount_fd < 0) return 1;
  int drive = -1;
  if (daze_dosfs_mounts_add_default(&mounts, mount_fd, 0, &drive) != DAZE_DOSFS_OK) return 1;
  daze_dosfs_handles_init(&handles);
  if (daze_dosfs_handles_bind_standard(&handles, 0, 1, 2, NULL) != DAZE_DOSFS_OK) return 1;
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  daze_dosfs_file_service_set_transfer_storage(&files, &transfer_storage);
  daze_dosfs_file_service_set_run_metrics(&files, &run_metrics);
  daze_dos_process_state_init(&process_state, 0x0ff0);
  daze_dos_memory_init(&dos_memory, 0x1000, 0xa000);
  const DazeDosInt21Context context = {
    .files = &files,
    .process_state = &process_state,
    .dos_memory = &dos_memory,
    .guest_memory = {.context = &memory, .read = memory_read, .write = memory_write},
    .transfer_observed = observe_transfer,
    .transfer_completed = complete_transfer,
    .transfer_context = &transfer_hooks,
    .indos_segment = 0x0600,
    .indos_offset = 0x0020,
    .dbcs_table_segment = 0x0600,
    .sda_segment = 0x0600,
    .sda_offset = 0x0030,
  };
  DazeDosInt21Result result;

  DazeDosInt21Request request = {.ax = 0x0bff};
  pass &= expect_result("console status", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 0x0b00) {
    fprintf(stderr, "console status AX=%04x\n", result.ax);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x06b7, .dx = 0x00ff, .flags = 0x0203};
  pass &= expect_result("direct console poll", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF | DAZE_DOS_INT21_FLAG_ZF,
                        DAZE_DOS_INT21_FLAG_ZF);
  if (result.ax != 0x0600) {
    fprintf(stderr, "direct console poll AX=%04x\n", result.ax);
    pass = 0;
  }

  memory.bytes[0x30] = 0xff;
  memory.bytes[0x31] = 0xff;
  request = (DazeDosInt21Request){.ax = 0x5d06};
  pass &= expect_result("swappable data area", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX | DAZE_DOS_INT21_REG_SI |
                          DAZE_DOS_INT21_REG_DS,
                        DAZE_DOS_INT21_FLAG_CF, 0);
  if (memory.bytes[0x30] != 0 || memory.bytes[0x31] != 0 || result.cx != 2 || result.dx != 2 ||
      result.si != 0x0030 || result.ds != 0x0600) {
    fprintf(stderr, "swappable data area result mismatch\n");
    pass = 0;
  }

  memcpy(memory.bytes + 0x80, "CREATED.BIN", sizeof("CREATED.BIN"));
  request = (DazeDosInt21Request){.ax = 0x3c00, .ds = 0x0600, .dx = 0x0080};
  pass &= expect_result("create file", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  const uint16_t created_handle = result.ax;

  request = (DazeDosInt21Request){.ax = 0x3e00, .bx = created_handle};
  pass &= expect_result("close file", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                        DAZE_DOS_INT21_FLAG_CF, 0);

  pass &=
    expect_result("close invalid handle", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 6) {
    fprintf(stderr, "close invalid handle AX=%04x\n", result.ax);
    pass = 0;
  }

  memcpy(memory.bytes + 0x80, "MISSING.TXT", sizeof("MISSING.TXT"));
  request = (DazeDosInt21Request){.ax = 0x3d00, .ds = 0x0600, .dx = 0x0080};
  pass &= expect_result("open missing file", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 2) {
    fprintf(stderr, "open missing file AX=%04x\n", result.ax);
    pass = 0;
  }

  memcpy(memory.bytes + 0x80, "FILE.TXT", sizeof("FILE.TXT"));
  request = (DazeDosInt21Request){.ax = 0x3d00, .ds = 0x0600, .dx = 0x0080};
  pass &= expect_result("open file", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  const uint16_t opened_handle = result.ax;

  request = (DazeDosInt21Request){.ax = 0x4200, .bx = opened_handle, .dx = 2};
  pass &= expect_result("seek nonzero", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_DX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 2 || result.dx != 0) {
    fprintf(stderr, "seek nonzero DX:AX=%04x:%04x\n", result.dx, result.ax);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x3e00, .bx = opened_handle};
  pass &= expect_result("close opened file", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                        DAZE_DOS_INT21_FLAG_CF, 0);

  memcpy(memory.bytes + 0x80, "\\", sizeof("\\"));
  request = (DazeDosInt21Request){.ax = 0x5a00, .ds = 0x0600, .dx = 0x0080};
  pass &= expect_result("create temp file", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  const uint16_t temp_handle = result.ax;
  if (strcmp((const char *)memory.bytes + 0x80, "\\DZ000000.TMP") != 0) {
    fprintf(stderr, "create temp file path=%s\n", memory.bytes + 0x80);
    pass = 0;
  }
  char temp_path[160];
  snprintf(temp_path, sizeof(temp_path), "%s/DZ000000.TMP", mount_template);
  if (access(temp_path, F_OK) != 0) {
    fprintf(stderr, "create temp file missing on host\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x3e00, .bx = temp_handle};
  pass &= expect_result("close temp file", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                        DAZE_DOS_INT21_FLAG_CF, 0);

  memcpy(memory.bytes + 0x80, "\\", sizeof("\\"));
  request = (DazeDosInt21Request){.ax = 0x5a00, .ds = 0x0600, .dx = 0x0080};
  pass &= expect_result("create temp unique", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  const uint16_t temp_handle2 = result.ax;
  if (strcmp((const char *)memory.bytes + 0x80, "\\DZ000001.TMP") != 0) {
    fprintf(stderr, "create temp unique path=%s\n", memory.bytes + 0x80);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x3e00, .bx = temp_handle2};
  pass &= expect_result("close temp unique", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                        DAZE_DOS_INT21_FLAG_CF, 0);

  snprintf(temp_path, sizeof(temp_path), "%s/DZ000002.TMP", mount_template);
  const int collision_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (collision_fd < 0) return 1;
  close(collision_fd);
  memcpy(memory.bytes + 0x80, "\\", sizeof("\\"));
  request = (DazeDosInt21Request){.ax = 0x5a00, .ds = 0x0600, .dx = 0x0080};
  pass &=
    expect_result("create temp collision", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (strcmp((const char *)memory.bytes + 0x80, "\\DZ000003.TMP") != 0) {
    fprintf(stderr, "create temp collision path=%s\n", memory.bytes + 0x80);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x3e00, .bx = result.ax};
  pass &= expect_result(
    "close temp collision", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);

  memcpy(memory.bytes + 0x80, "NODIR", sizeof("NODIR"));
  request = (DazeDosInt21Request){.ax = 0x5a00, .ds = 0x0600, .dx = 0x0080};
  pass &=
    expect_result("create temp no slash", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 3) {
    fprintf(stderr, "create temp no slash AX=%04x\n", result.ax);
    pass = 0;
  }

  memcpy(memory.bytes + 0x80, "\\MISSING\\", sizeof("\\MISSING\\"));
  request = (DazeDosInt21Request){.ax = 0x5a00, .ds = 0x0600, .dx = 0x0080};
  pass &=
    expect_result("create temp missing dir", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  /* Missing parents report FILE_NOT_FOUND (2), not PATH_NOT_FOUND. */
  if (result.ax != 2) {
    fprintf(stderr, "create temp missing dir AX=%04x\n", result.ax);
    pass = 0;
  }

  memcpy(memory.bytes + 0x80, "FILE.TXT", sizeof("FILE.TXT"));
  request = (DazeDosInt21Request){.ax = 0x3d00, .ds = 0x0600, .dx = 0x0080};
  pass &=
    expect_result("open transfer source", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  const uint16_t read_handle = result.ax;
  request = (DazeDosInt21Request){.ax = 0x4000, .bx = read_handle};
  pass &= expect_result("zero write readonly handle",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  pass &= result.ax == 5;

  request =
    (DazeDosInt21Request){.ax = 0x3f00, .bx = read_handle, .cx = 8, .ds = 0x0600, .dx = 0x00a0};
  pass &= expect_result("short read", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 4 || memcmp(memory.bytes + 0xa0, "data", 4) != 0) {
    fprintf(stderr, "short read result mismatch\n");
    pass = 0;
  }
  const uint8_t *const transfer_bytes = transfer_storage.bytes;
  if (transfer_bytes == NULL || transfer_storage.capacity < 8) {
    fprintf(stderr, "short read did not retain transfer storage\n");
    pass = 0;
  }
  if (run_metrics.read_calls != 1 || run_metrics.read_requested_bytes != 8 ||
      run_metrics.read_bytes != 4 || run_metrics.transfer_buffer_resizes != 1 ||
      run_metrics.transfer_buffer_peak != 8) {
    fprintf(stderr, "short read transfer metrics mismatch\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x3f00, .bx = read_handle, .ds = 0x0600, .dx = 0x00a0};
  pass &= expect_result("zero-length read", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 0) {
    fprintf(stderr, "zero-length read AX=%04x\n", result.ax);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4200, .bx = read_handle};
  if (daze_dos_int21_dispatch(&context, &request, &result) != DAZE_DOS_INT21_DISPATCH_OK ||
      result.disposition != DAZE_DOS_INT21_HANDLED || result.ax != 0 || result.dx != 0)
    return 1;

  request = (DazeDosInt21Request){.ax = 0x3f00, .bx = 99, .ds = 0x0600, .dx = 0x00a0};
  pass &= expect_result("read invalid handle", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 6) {
    fprintf(stderr, "read invalid handle AX=%04x\n", result.ax);
    pass = 0;
  }

  memory.fail_write = 1;
  request =
    (DazeDosInt21Request){.ax = 0x3f00, .bx = read_handle, .cx = 1, .ds = 0x0600, .dx = 0x00a0};
  pass &= expect_result(
    "read guest-memory failure", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE, &result, DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);
  memory.fail_write = 0;

  memcpy(memory.bytes + 0x80, "WRITE.BIN", sizeof("WRITE.BIN"));
  request = (DazeDosInt21Request){.ax = 0x3c00, .ds = 0x0600, .dx = 0x0080};
  if (daze_dos_int21_dispatch(&context, &request, &result) != DAZE_DOS_INT21_DISPATCH_OK ||
      result.disposition != DAZE_DOS_INT21_HANDLED ||
      (result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0)
    return 1;
  const uint16_t write_handle = result.ax;
  memcpy(memory.bytes + 0xa0, "write", 5);
  request =
    (DazeDosInt21Request){.ax = 0x4000, .bx = write_handle, .cx = 5, .ds = 0x0600, .dx = 0x00a0};
  pass &= expect_result("write", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 5) {
    fprintf(stderr, "write AX=%04x\n", result.ax);
    pass = 0;
  }
  if (transfer_storage.bytes != transfer_bytes) {
    fprintf(stderr, "write did not reuse transfer storage\n");
    pass = 0;
  }
  if (run_metrics.write_calls != 1 || run_metrics.write_requested_bytes != 5 ||
      run_metrics.write_bytes != 5) {
    fprintf(stderr, "write transfer metrics mismatch\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4000, .bx = write_handle, .ds = 0x0600, .dx = 0x00a0};
  pass &= expect_result("zero-length write", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 0) {
    fprintf(stderr, "zero-length write AX=%04x\n", result.ax);
    pass = 0;
  }

  memory.fail_read = 1;
  request =
    (DazeDosInt21Request){.ax = 0x4000, .bx = write_handle, .cx = 1, .ds = 0x0600, .dx = 0x00a0};
  pass &= expect_result(
    "write guest-memory failure", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE, &result, DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);
  memory.fail_read = 0;

  int output_fd = -1;
  struct stat output_stat;
  pass &= daze_dosfs_handles_flush_and_get(&handles, write_handle, &output_fd) == DAZE_DOSFS_OK;
  const off_t lengths[] = {2, 8};
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
    pass &= lseek(output_fd, lengths[i], SEEK_SET) == lengths[i];
    request = (DazeDosInt21Request){.ax = 0x4000, .bx = write_handle};
    pass &= expect_result("zero write changes length",
                          daze_dos_int21_dispatch(&context, &request, &result),
                          DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                          DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
    pass &= fstat(output_fd, &output_stat) == 0 && output_stat.st_size == lengths[i];
    pass &= lseek(output_fd, 0, SEEK_CUR) == lengths[i];
  }
  uint8_t extended[8];
  pass &= pread(output_fd, extended, sizeof(extended), 0) == sizeof(extended) &&
          memcmp(extended, "wr\0\0\0\0\0\0", sizeof(extended)) == 0;

  request = (DazeDosInt21Request){.ax = 0x4000, .bx = 99, .ds = 0x0600, .dx = 0x00a0};
  pass &=
    expect_result("write invalid handle", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 6) {
    fprintf(stderr, "write invalid handle AX=%04x\n", result.ax);
    pass = 0;
  }

  int host_error_pipe[2];
  uint16_t host_error_handle = 0;
  if (pipe(host_error_pipe) != 0 ||
      daze_dosfs_handles_adopt(&handles, host_error_pipe[0], &host_error_handle) != DAZE_DOSFS_OK)
    return 1;
  close(host_error_pipe[0]);
  close(host_error_pipe[1]);
  request = (DazeDosInt21Request){
    .ax = 0x3f00, .bx = host_error_handle, .cx = 1, .ds = 0x0600, .dx = 0x00a0};
  pass &= expect_result("read host failure", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 1 || transfer_hooks.observed < 6 || transfer_hooks.completed < 4) {
    fprintf(stderr, "transfer hook/result mismatch AX=%04x observed=%d completed=%d\n", result.ax,
            transfer_hooks.observed, transfer_hooks.completed);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x2aff};
  pass &= expect_result("date", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX,
                        DAZE_DOS_INT21_FLAG_CF, 0);
  if ((result.ax & 0xff00u) != 0x2a00 || result.cx < 2000 || (result.dx >> 8) == 0 ||
      (uint8_t)result.dx == 0) {
    fprintf(stderr, "date result invalid\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x2c7f};
  pass &= expect_result("clock", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.cx != 0 || result.dx != 0) {
    fprintf(stderr, "clock result invalid\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x30ff};
  pass &= expect_result("DOS version", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_BX | DAZE_DOS_INT21_REG_CX,
                        DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 0x0005 || result.bx != 0 || result.cx != 0) {
    fprintf(stderr, "DOS version result invalid\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x3400};
  pass &= expect_result("InDOS pointer", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_BX | DAZE_DOS_INT21_REG_ES, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.bx != 0x0020 || result.es != 0x0600 || memory.bytes[0x20] != 0) {
    fprintf(stderr, "InDOS result invalid\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x5000, .bx = 0x1234};
  pass &= expect_result("set current PSP", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                        DAZE_DOS_INT21_FLAG_CF, 0);
  if (process_state.psp_segment != 0x1234) {
    fprintf(stderr, "set current PSP result invalid\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x5100};
  pass &= expect_result("current PSP", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_BX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.bx != 0x1234) {
    fprintf(stderr, "current PSP result invalid\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4c7f};
  pass &=
    expect_result("terminate classification", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_TERMINATED, 0, 0, 0);
  if (result.termination_status != 0x7f) {
    fprintf(stderr, "terminate status=%02x\n", result.termination_status);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x3102, .dx = 0x059c};
  pass &= expect_result("resident terminate classification",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_TERMINATED, 0, 0, 0);
  if (result.termination_status != 2) {
    fprintf(stderr, "resident terminate status=%02x\n", result.termination_status);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4b00};
  pass &= expect_result("EXEC classification", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_EXEC, 0, 0, 0);

  request = (DazeDosInt21Request){.ax = 0x4b01};
  pass &=
    expect_result("unsupported EXEC mode", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);

  request = (DazeDosInt21Request){.ax = 0x1900};
  pass &= expect_result("current drive", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 0x1902) {
    fprintf(stderr, "current drive AX=%04x\n", result.ax);
    pass = 0;
  }

  memcpy(memory.bytes + 0xa0, "C:\\GO32.EXE", 12);
  request =
    (DazeDosInt21Request){.ax = 0x2901, .ds = 0x0600, .si = 0x00a0, .es = 0x0600, .di = 0x00c0};
  pass &= expect_result("FCB parse", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_SI, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 0x2900 || result.si != 0x00ab || memory.bytes[0xc0] != 3 ||
      memcmp(memory.bytes + 0xc1, "GO32    EXE", 11) != 0) {
    fprintf(stderr, "FCB parse result mismatch\n");
    pass = 0;
  }

  memcpy(memory.bytes + 0x60, "FILE.TXT", 9);
  request = (DazeDosInt21Request){.ax = 0x4300, .ds = 0x0600, .dx = 0x0060};
  pass &= expect_result("file attributes", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_CX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.cx != 0x20) {
    fprintf(stderr, "file attributes CX=%04x\n", result.cx);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4301, .cx = 0, .ds = 0x0600, .dx = 0x0060};
  pass &= expect_result(
    "set normal file attributes", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);
  request.cx = 1;
  pass &= expect_result("unsupported set file attribute bits",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 5) {
    fprintf(stderr, "unsupported file attributes DOS error=%u\n", result.ax);
    pass = 0;
  }
  request.cx = 0;
  mounts.readonly[drive] = 1;
  pass &= expect_result("set attributes on read-only mount",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 5) {
    fprintf(stderr, "read-only attribute mount DOS error=%u\n", result.ax);
    pass = 0;
  }
  mounts.readonly[drive] = 0;
  memcpy(memory.bytes + 0x60, "C:\\FILE.TXT", 12);
  request = (DazeDosInt21Request){.ax = 0x4301, .cx = 0, .ds = 0x0600, .dx = 0x0060};
  pass &= expect_result(
    "set attributes with explicit drive", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);
  memcpy(memory.bytes + 0x60, "?:FILE.TXT", 11);
  request = (DazeDosInt21Request){.ax = 0x4301, .cx = 0, .ds = 0x0600, .dx = 0x0060};
  pass &= expect_result("set attributes on invalid drive",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 15) {
    fprintf(stderr, "invalid-drive attribute DOS error=%u\n", result.ax);
    pass = 0;
  }
  memcpy(memory.bytes + 0x60, "[:FILE.TXT", 11);
  pass &= expect_result("set attributes on out-of-range drive",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 15) {
    fprintf(stderr, "out-of-range attribute drive DOS error=%u\n", result.ax);
    pass = 0;
  }

  memcpy(memory.bytes + 0x60, "DELETE.TXT", 11);
  request = (DazeDosInt21Request){.ax = 0x4100, .ds = 0x0600, .dx = 0x0060};
  pass &= expect_result("delete file", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                        DAZE_DOS_INT21_FLAG_CF, 0);
  if (access(delete_file, F_OK) == 0) {
    fprintf(stderr, "delete file still present\n");
    pass = 0;
  }

  memory.bytes[0xf0] = 0xff;
  request = (DazeDosInt21Request){.ax = 0x4700, .ds = 0x0600, .si = 0x00f0, .dx = 0};
  pass &= expect_result("current directory", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                        DAZE_DOS_INT21_FLAG_CF, 0);
  if (memory.bytes[0xf0] != 0) {
    fprintf(stderr, "current directory output mismatch\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4700, .ds = 0x0600, .si = 0x00f0, .dx = 4};
  pass &= expect_result("current directory invalid drive",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 15) {
    fprintf(stderr, "current directory invalid AX=%04x\n", result.ax);
    pass = 0;
  }

  mounts.fds[3] = mount_fd;
  mounts.fds[23] = mount_fd;
  mounts.default_drive = 23;
  const uint8_t drive_queries[] = {0, 1, 2, 3, 4, 24, 26, 27, 255};
  for (size_t i = 0; i < sizeof(drive_queries); ++i) {
    const uint8_t dl = drive_queries[i];
    const int valid = dl == 0 || dl == 3 || dl == 4 || dl == 24;
    memory.bytes[0xf0] = 0xff;
    request = (DazeDosInt21Request){.ax = 0x4700, .ds = 0x0600, .si = 0x00f0, .dx = dl};
    pass &=
      expect_result("mounted directory drive", daze_dos_int21_dispatch(&context, &request, &result),
                    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                    valid ? 0 : DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF,
                    valid ? 0 : DAZE_DOS_INT21_FLAG_CF);
    pass &= valid ? memory.bytes[0xf0] == 0 : result.ax == 15 && memory.bytes[0xf0] == 0xff;
  }
  mounts.fds[3] = mounts.fds[23] = -1;
  mounts.default_drive = 2;

  request = (DazeDosInt21Request){.ax = 0x1a00, .ds = 0x0600, .dx = 0x0040};
  pass &= expect_result("set DTA", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                        DAZE_DOS_INT21_FLAG_CF, 0);
  if (process_state.dta_segment != 0x0600 || process_state.dta_offset != 0x0040) {
    fprintf(stderr, "set DTA state mismatch\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x2f00};
  pass &= expect_result("get DTA", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_BX | DAZE_DOS_INT21_REG_ES, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.bx != 0x0040 || result.es != 0x0600) {
    fprintf(stderr, "get DTA result mismatch bx=%04x es=%04x\n", result.bx, result.es);
    pass = 0;
  }

  daze_dos_process_state_set_dta(&process_state, 0x0ff0, 0x0080);
  request = (DazeDosInt21Request){.ax = 0x2f00};
  pass &= expect_result("get DTA default", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_BX | DAZE_DOS_INT21_REG_ES, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.bx != 0x0080 || result.es != 0x0ff0) {
    fprintf(stderr, "get DTA default result mismatch bx=%04x es=%04x\n", result.bx, result.es);
    pass = 0;
  }

  daze_dos_process_state_record_child_termination(&process_state, 7, 3);
  request = (DazeDosInt21Request){.ax = 0x4d00};
  pass &= expect_result("child status", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 0x0307 || process_state.child_status_available) {
    fprintf(stderr, "child status result mismatch\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x1a00, .ds = 0x0600, .dx = 0x0040};
  daze_dos_int21_dispatch(&context, &request, &result);
  memcpy(memory.bytes + 0x80, "*.TXT", 6);
  request = (DazeDosInt21Request){.ax = 0x4e00, .cx = 0, .ds = 0x0600, .dx = 0x0080};
  pass &= expect_result("find first", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0,
                        DAZE_DOS_INT21_FLAG_CF, 0);
  if (memcmp(memory.bytes + 0x40 + 0x1e, "FILE.TXT", 8) != 0) {
    fprintf(stderr, "find first DTA mismatch\n");
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4f00};
  pass &= expect_result("find next exhausted", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 18) {
    fprintf(stderr, "find next exhausted AX=%04x\n", result.ax);
    pass = 0;
  }

  daze_dos_process_state_set_dta(&process_state, 0x0601, 0);
  request = (DazeDosInt21Request){.ax = 0x4e00, .cx = 0, .ds = 0x0600, .dx = 0x0080};
  pass &=
    expect_result("find first invalid DTA", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 18) {
    fprintf(stderr, "find first invalid DTA AX=%04x\n", result.ax);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4400, .bx = 0};
  pass &= expect_result("ioctl valid handle", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_DX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.dx != 0) {
    fprintf(stderr, "ioctl valid DX=%04x\n", result.dx);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4400, .bx = 99};
  pass &=
    expect_result("ioctl invalid handle", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 6) {
    fprintf(stderr, "ioctl invalid AX=%04x\n", result.ax);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x4600, .bx = 0, .cx = 5};
  pass &= expect_result("force duplicate", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 5) {
    fprintf(stderr, "force duplicate AX=%04x\n", result.ax);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x5700, .bx = 0};
  pass &=
    expect_result("file time valid handle", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.cx != 0 || result.dx != 0x2821) {
    fprintf(stderr, "file time valid CX:DX=%04x:%04x\n", result.cx, result.dx);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x5700, .bx = 99};
  pass &=
    expect_result("file time invalid handle", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 6) {
    fprintf(stderr, "file time invalid AX=%04x\n", result.ax);
    pass = 0;
  }

  const int timestamp_fd = open(mount_file, O_RDONLY);
  uint16_t timestamp_handle = 0;
  struct stat timestamp_before, timestamp_after;
  if (timestamp_fd < 0 || fstat(timestamp_fd, &timestamp_before) != 0 ||
      daze_dosfs_handles_adopt(&handles, timestamp_fd, &timestamp_handle) != DAZE_DOSFS_OK)
    return 1;
  request = (DazeDosInt21Request){
    .ax = 0x5701, .bx = timestamp_handle, .cx = 0x1234, .dx = 0x5678, .flags = 0x0203};
  pass &= expect_result(
    "set file time valid handle", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);
  if (fstat(timestamp_fd, &timestamp_after) != 0 ||
#if defined(__APPLE__)
      timestamp_before.st_mtimespec.tv_sec != timestamp_after.st_mtimespec.tv_sec ||
      timestamp_before.st_mtimespec.tv_nsec != timestamp_after.st_mtimespec.tv_nsec ||
      timestamp_before.st_ctimespec.tv_sec != timestamp_after.st_ctimespec.tv_sec ||
      timestamp_before.st_ctimespec.tv_nsec != timestamp_after.st_ctimespec.tv_nsec
#else
      timestamp_before.st_mtim.tv_sec != timestamp_after.st_mtim.tv_sec ||
      timestamp_before.st_mtim.tv_nsec != timestamp_after.st_mtim.tv_nsec ||
      timestamp_before.st_ctim.tv_sec != timestamp_after.st_ctim.tv_sec ||
      timestamp_before.st_ctim.tv_nsec != timestamp_after.st_ctim.tv_nsec
#endif
  ) {
    fputs("virtual set file time changed host metadata\n", stderr);
    pass = 0;
  }
  request.ax = 0x5700;
  pass &=
    expect_result("get after set file time", daze_dos_int21_dispatch(&context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX, DAZE_DOS_INT21_FLAG_CF, 0);
  pass &= result.cx == 0 && result.dx == 0x2821;
  request.ax = 0x5701;
  request.bx = 99;
  pass &= expect_result("set file time invalid handle",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  pass &= result.ax == 6;
  request.ax = 0x5702;
  pass &= expect_result("unsupported file time operation",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);

  request = (DazeDosInt21Request){.ax = 0x6300};
  pass &= expect_result("dbcs table", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_DS | DAZE_DOS_INT21_REG_SI, DAZE_DOS_INT21_FLAG_CF, 0);
  if (memory.segment != 0x0600 || memory.offset != 0 || memory.size != 2 || memory.bytes[0] != 0 ||
      memory.bytes[1] != 0 || result.ds != 0x0600 || result.si != 0) {
    fprintf(stderr, "dbcs table result mismatch\n");
    pass = 0;
  }

  memory.fail_write = 1;
  request = (DazeDosInt21Request){.ax = 0x6300};
  pass &= expect_result("dbcs memory failure", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE, &result, DAZE_DOS_INT21_UNSUPPORTED,
                        0, 0, 0);
  memory.fail_write = 0;

  request = (DazeDosInt21Request){.ax = 0x6700, .bx = DAZE_DOSFS_MAX_HANDLES + 1};
  pass &= expect_result("handle count error", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 4) {
    fprintf(stderr, "handle count error AX=%04x\n", result.ax);
    pass = 0;
  }

  DazeDosMemory conventional_memory;
  daze_dos_memory_init(&conventional_memory, 0x1000, 0x1020);
  PreRelease hook = {.succeed = 0};
  DazeDosInt21Context memory_context = context;
  memory_context.dos_memory = &conventional_memory;
  memory_context.pre_release = pre_release;
  memory_context.pre_release_context = &hook;
  request = (DazeDosInt21Request){.ax = 0x4800, .bx = 0x0010};
  pass &=
    expect_result("allocate memory", daze_dos_int21_dispatch(&memory_context, &request, &result),
                  DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                  DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 0x1000) {
    fprintf(stderr, "allocate memory AX=%04x\n", result.ax);
    pass = 0;
  }
  request = (DazeDosInt21Request){.ax = 0x4900, .es = 0x1000};
  pass &= expect_result("release hook failure",
                        daze_dos_int21_dispatch(&memory_context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 8 || hook.calls != 1 || !conventional_memory.allocations[0].in_use) {
    fprintf(stderr, "release hook failure mutated allocation\n");
    pass = 0;
  }
  hook.succeed = 1;
  pass &= expect_result(
    "release memory", daze_dos_int21_dispatch(&memory_context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);
  request = (DazeDosInt21Request){.ax = 0x4900, .es = 0x1000};
  pass &= expect_result("release invalid block",
                        daze_dos_int21_dispatch(&memory_context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 9) {
    fprintf(stderr, "release invalid AX=%04x\n", result.ax);
    pass = 0;
  }

  daze_dos_memory_init(&conventional_memory, 0x2000, 0x2040);
  memory_context.pre_release = NULL;
  memory_context.pre_release_context = NULL;
  request = (DazeDosInt21Request){.ax = 0x4800, .bx = 0x0010};
  (void)daze_dos_int21_dispatch(&memory_context, &request, &result);
  request = (DazeDosInt21Request){.ax = 0x4a00, .es = 0x2000, .bx = 0x0020};
  pass &= expect_result(
    "resize memory", daze_dos_int21_dispatch(&memory_context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);
  request = (DazeDosInt21Request){.ax = 0x4a00, .es = 0x2000, .bx = 0x0100};
  pass &= expect_result(
    "resize memory failure", daze_dos_int21_dispatch(&memory_context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
    DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_BX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  if (result.ax != 8) {
    fprintf(stderr, "resize failure AX=%04x\n", result.ax);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x5801, .bx = 2};
  pass &= expect_result(
    "set allocation strategy", daze_dos_int21_dispatch(&memory_context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED, 0, DAZE_DOS_INT21_FLAG_CF, 0);
  request = (DazeDosInt21Request){.ax = 0x5800};
  pass &= expect_result("get allocation strategy",
                        daze_dos_int21_dispatch(&memory_context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX, DAZE_DOS_INT21_FLAG_CF, 0);
  if (result.ax != 2) {
    fprintf(stderr, "allocation strategy AX=%04x\n", result.ax);
    pass = 0;
  }

  request = (DazeDosInt21Request){.ax = 0x3700, .dx = 0xabcd, .flags = 0x0203};
  pass &= expect_result("get switch character", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
                        DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_DX,
                        DAZE_DOS_INT21_FLAG_CF, 0);
  pass &= result.ax == 0x3700 && result.dx == 0xab2f;

  request = (DazeDosInt21Request){.ax = 0x3701};
  pass &= expect_result("unsupported switch character subfunction",
                        daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);

  request = (DazeDosInt21Request){.ax = 0x1200};
  pass &= expect_result("unsupported", daze_dos_int21_dispatch(&context, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);

  pass &= expect_result("invalid context", daze_dos_int21_dispatch(NULL, &request, &result),
                        DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT, &result,
                        DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);

  DazeDosMemory allocator_before = conventional_memory;
  request = (DazeDosInt21Request){.ax = 0x4800, .bx = 0xffff};
  pass &= expect_result(
    "allocation exhaustion", daze_dos_int21_dispatch(&memory_context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_OK, &result, DAZE_DOS_INT21_HANDLED,
    DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_BX, DAZE_DOS_INT21_FLAG_CF, DAZE_DOS_INT21_FLAG_CF);
  pass &= result.ax == 8 && result.bx == 0x20 &&
          memcmp(&conventional_memory, &allocator_before, sizeof(conventional_memory)) == 0;
  memset(memory.bytes + 0x100, 'X', 128);
  request = (DazeDosInt21Request){.ax = 0x3d00, .ds = 0x0600, .dx = 0x100};
  DazeDosfsHandles handles_before = handles;
  pass &= expect_result(
    "unterminated guest path", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE, &result, DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);
  pass &= memcmp(&handles, &handles_before, sizeof(handles)) == 0;
  memory.fail_write = 1;
  const uint8_t indos_before = memory.bytes[context.indos_offset];
  request = (DazeDosInt21Request){.ax = 0x3400};
  pass &= expect_result(
    "InDOS rejected write", daze_dos_int21_dispatch(&context, &request, &result),
    DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE, &result, DAZE_DOS_INT21_UNSUPPORTED, 0, 0, 0);
  pass &= memory.bytes[context.indos_offset] == indos_before;
  memory.fail_write = 0;

  daze_dos_process_state_dispose(&process_state);
  daze_dosfs_transfer_storage_dispose(&transfer_storage);
  daze_dosfs_handles_close_all(&handles);
  close(mount_fd);
  unlink(mount_file);
  rmdir(mount_template);
  pass &= display_string_contract();
  pass &= rename_contract();
  if (!pass) return 1;
  puts("int21 service: passed");
  return 0;
}
