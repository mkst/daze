#include "unicorn_run.c"
#include "descriptor.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
  DazeUnicornContext *context;
  int mode;
  unsigned visits;
  uint16_t reply_ax;
} Boundary;

static void boundary(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
  (void)size;
  Boundary *test = user_data;
  DazeUnicornContext *context = test->context;
  if (address == 0x10002) test->reply_ax = get_reg16(uc, UC_X86_REG_AX);
  if (address != 0x10000) return;
  if (test->visits++ != 0) {
    assert(test->mode == 4 && context->run.terminated);
    uc_emu_stop(uc);
    return;
  }
  context->engine.last_code_address = address;
  if (test->mode == 0) {
    context->run.resume_address = 0x10002;
    context->run.use_resume_address = 1;
  } else if (test->mode == 1) {
    context->run.continue_run = 1;
  } else {
    context->run.stopped = 1;
    context->run.interrupt_number = test->mode == 2   ? 0x15
                                    : test->mode == 3 ? 0x11
                                    : test->mode == 4 ? 0x21
                                                      : 0x60;
    set_reg16(uc, UC_X86_REG_AX, test->mode == 2 ? 0xc000 : test->mode == 4 ? 0x3127 : 0);
  }
  uc_emu_stop(uc);
}

static void loop_case(int mode, int metrics) {
  uc_engine *uc;
  assert(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  assert(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  DazeUnicornContext context = {0};
  context.engine.metrics.enabled = metrics;
  set_reg16(uc, UC_X86_REG_CS, 0x1000);
  set_reg16(uc, UC_X86_REG_IP, 0);
  set_reg16(uc, UC_X86_REG_SS, 0x3000);
  set_reg16(uc, UC_X86_REG_SP, 0x800);
  const uint8_t program[] = {0xb0, 0x00,       /* mov al,0 */
                             0xb8, 0x2a, 0x4c, /* mov ax,0x4c2a */
                             0xcd, 0x21};      /* int 0x21 */
  assert(uc_mem_write(uc, 0x10000, program, sizeof(program)) == UC_ERR_OK);
  uint32_t entry = 0x10000;
  if (mode == 2) {
    const uint16_t selectors[] = {8, 0x10, 0x18, 0x28};
    const uint32_t bases[] = {0x10000, 0x10100, 0x30000, 0x2000};
    for (size_t i = 0; i < 4; ++i) {
      uint8_t descriptor[8];
      daze_dpmi_descriptor_encode(descriptor, bases[i], 0xffff, i == 0 || i == 3 ? 0x9a : 0x92, 0);
      assert(uc_mem_write(uc, k_dpmi_gdt_address + selectors[i], descriptor, 8) == UC_ERR_OK);
    }
    uc_x86_mmr gdtr = {.base = k_dpmi_gdt_address, .limit = 0x2f};
    assert(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) == UC_ERR_OK);
    set_reg32(uc, UC_X86_REG_CR0, 1);
    set_reg16(uc, UC_X86_REG_CS, 8);
    set_reg16(uc, UC_X86_REG_SS, 0x18);
    set_reg16(uc, UC_X86_REG_SP, 0x800);
    entry = 0x80;
  }
  if (mode == 6) {
    const uint8_t fault[] = {0xa1, 0x00, 0x20}; /* mov ax,[2000h] */
    assert(uc_mem_write(uc, 0x10000, fault, sizeof(fault)) == UC_ERR_OK);
    assert(uc_mem_unmap(uc, 0x2000, 0x1000) == UC_ERR_OK);
  }
  if (mode == 7) {
    const uint8_t hlt = 0xf4; /* hlt */
    assert(uc_mem_write(uc, 0x10000, &hlt, 1) == UC_ERR_OK);
  }
  Boundary test = {.context = &context, .mode = mode};
  uc_hook code_hook, interrupt_hook;
  if (mode < 6)
    assert(uc_hook_add(uc, &code_hook, UC_HOOK_CODE, boundary, &test, 1, 0) == UC_ERR_OK);
  DazeUnicornInterruptContext interrupt = {.context = &context};
  assert(uc_hook_add(uc, &interrupt_hook, UC_HOOK_INTR, daze_on_interrupt, &interrupt, 1, 0) ==
         UC_ERR_OK);
  DazeCommandResult result = run_unicorn_loop(uc, &context, NULL, entry);
  assert(result.guest_execution_started);
  assert(result.disposition == (mode < 5 ? DAZE_COMMAND_COMPLETED : DAZE_COMMAND_POSTSTART_FAILED));
  if (mode < 5) {
    assert(result.dos_exit_code == (mode == 4 ? 0x27 : 0x2a));
    assert(context.engine.metrics.emulation_runs == 2);
    DazeResumeKind kind = mode < 2    ? DAZE_RESUME_DIRECT
                          : mode == 2 ? DAZE_RESUME_AFTER_DISPATCH_ADDRESS
                          : mode == 3 ? DAZE_RESUME_AFTER_DISPATCH_NEXT
                                      : DAZE_RESUME_AFTER_DISPATCH_RESTART;
    assert(context.engine.metrics.resume_counts[kind] == (unsigned)metrics);
    if (mode == 3) assert(test.reply_ax == 0x20);
  } else
    assert(context.engine.metrics.emulation_runs == 1);
  assert(context.process.child_process.parent_context == NULL);
}

static DazePreparedLaunch launch_fixture(uint8_t image[64]) {
  memset(image, 0, 64);
  image[0] = 'M';
  image[1] = 'Z';
  daze_write_u16(image + 2, 64);
  daze_write_u16(image + 4, 1);
  daze_write_u16(image + 8, 2);
  daze_write_u16(image + 0x10, 0x800);
  daze_write_u16(image + 0x18, 0x1c);
  const uint8_t code[] = {0xb8, 0x25, 0x4c, /* mov ax,0x4c25 */
                          0xcd, 0x21};      /* int 0x21 */
  memcpy(image + 32, code, sizeof(code));
  DazePreparedLaunch launch = {.image = {image, 64},
                               .image_address = 0x10000,
                               .guest_path = "TEST.EXE",
                               .allocation_start = 0x3000};
  assert(daze_mz_parse_header(image, 64, &launch.header));
  daze_dosfs_mounts_init(&launch.mounts);
  daze_dosfs_handles_init(&launch.handles);
  return launch;
}

static void initialization(void) {
  uint8_t image[64];
  DazePreparedLaunch launch = launch_fixture(image);
  DazeUnicornContext context = {0};
  uc_engine *uc = NULL;
  assert(initialize_unicorn_prepared(NULL, &launch, &context) == 3);
  assert(initialize_unicorn_prepared(&uc, NULL, &context) == 3);
  assert(initialize_unicorn_prepared(&uc, &launch, NULL) == 3);
  DazePreparedLaunch invalid = launch;
  invalid.image.bytes = NULL;
  assert(initialize_unicorn_prepared(&uc, &invalid, &context) == 3 && uc == NULL);
  invalid = launch;
  invalid.image_address = k_memory_size;
  assert(initialize_unicorn_prepared(&uc, &invalid, &context) == 3 && uc == NULL);
  invalid = launch;
  invalid.env_var_count = DAZE_PROCESS_ENV_MAX_EXTRA_VARS + 1;
  assert(initialize_unicorn_prepared(&uc, &invalid, &context) == 3 && uc == NULL);
  assert(initialize_unicorn_prepared(&uc, &launch, &context) == 0);
  assert(uc != NULL && context.process.resident_image_end == 0x10020);
  assert(uc_context_alloc(uc, &context.process.child_process.parent_context) == UC_ERR_OK);
  context.process.dos_process.find.directory = opendir("/tmp");
  assert(context.process.dos_process.find.directory != NULL);
  int search_fd = dirfd(context.process.dos_process.find.directory);
  dispose_unicorn_operation(uc, &context);
  assert(context.process.child_process.parent_context == NULL &&
         context.process.dos_process.find.directory == NULL);
  assert(fcntl(search_fd, F_GETFD) == -1 && errno == EBADF);
  dispose_unicorn_operation(NULL, &context);
}

static void prepared_trace(void) {
  const char *names[] = {"DAZE_TRACE",
                         "DAZE_TRACE_BEGIN",
                         "DAZE_TRACE_END",
                         "DAZE_DIAGNOSTIC_HISTORY",
                         "DAZE_TRACE_DUMP_ADDRESS",
                         "DAZE_TRACE_DUMP_SIZE"};
  char *saved[6] = {0};
  for (size_t i = 0; i < 6; ++i) {
    const char *value = getenv(names[i]);
    if (value != NULL) {
      saved[i] = strdup(value);
      assert(saved[i] != NULL);
    }
    assert(unsetenv(names[i]) == 0);
  }
  uint8_t image[64];
  DazePreparedLaunch launch = launch_fixture(image);
  DazeUnicornContext context = {0};
  assert(setenv("DAZE_TRACE", "1", 1) == 0);
  DazeCommandResult result = daze_unicorn_run_prepared(&launch, &context, "TEST.EXE");
  assert(result.disposition == DAZE_COMMAND_PRESTART_REJECTED && !result.guest_execution_started);
  assert(setenv("DAZE_TRACE_BEGIN", "0x10000", 1) == 0);
  assert(setenv("DAZE_TRACE_END", "0x10010", 1) == 0);
  result = daze_unicorn_run_prepared(&launch, &context, "TEST.EXE");
  assert(result.disposition == DAZE_COMMAND_COMPLETED && result.dos_exit_code == 0x25 &&
         result.guest_execution_started);
  assert(context.engine.full_code_hook && context.engine.metrics.guest_instruction_count_available);
  for (size_t i = 0; i < 6; ++i) {
    if (saved[i] != NULL) {
      assert(setenv(names[i], saved[i], 1) == 0);
      free(saved[i]);
    } else
      assert(unsetenv(names[i]) == 0);
  }
}

int main(void) {
  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  for (int metrics = 0; metrics < 2; ++metrics)
    for (int mode = 0; mode < 8; ++mode)
      loop_case(mode, metrics);
  initialization();
  prepared_trace();
  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char text[32768] = {0};
  assert(fread(text, 1, sizeof(text) - 1, capture) > 0);
  assert(strstr(text, "emulation stopped with Invalid memory read") != NULL);
  assert(strstr(text, "invalid Unicorn trace configuration") != NULL);
  assert(strstr(text, "Unicorn trace enabled for linear range 00010000..00010010") != NULL);
  assert(strstr(text, "cannot prepare MZ image and relocations") != NULL);
  assert(strstr(text, "unable to initialise guest memory") != NULL);
  fclose(capture);
  return 0;
}
