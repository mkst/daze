#include "backend/unicorn/int21_adapter.c"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

static void call(uc_engine *uc, DazeUnicornContext *context, DazeDosfsFileService *files,
                 uint16_t ax, uint16_t bx, uint16_t dx, uint16_t expected, int carry) {
  set_reg16(uc, UC_X86_REG_AX, ax);
  set_reg16(uc, UC_X86_REG_BX, bx);
  set_reg16(uc, UC_X86_REG_DX, dx);
  set_reg16(uc, UC_X86_REG_IP, 0x100);
  set_reg32(uc, UC_X86_REG_EFLAGS, 0x243);
  assert(
    daze_unicorn_int21_dispatch(uc, &context->engine, &context->run, &context->process, files));
  assert(get_reg16(uc, UC_X86_REG_AX) == expected);
  assert((get_reg32(uc, UC_X86_REG_EFLAGS) & 1) == (unsigned)carry);
  assert(get_reg16(uc, UC_X86_REG_IP) == 0x102);
}

int main(void) {
  uc_engine *uc;
  assert(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  assert(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  DazeUnicornContext context = {0};
  daze_dos_process_state_init(&context.process.dos_process, 0x1000);
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  FILE *output = tmpfile();
  assert(output != NULL);
  assert(daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, fileno(output), STDERR_FILENO,
                                          NULL) == DAZE_DOSFS_OK);
  call(uc, &context, &files, 0x0200, 0, 'A', 0x0241, 1);
  call(uc, &context, &files, 0x0600, 0, 'B', 0x0642, 0);
  assert(!(get_reg32(uc, UC_X86_REG_EFLAGS) & 0x40));
  assert(context.engine.metrics.host_write_calls == 2 &&
         context.engine.metrics.host_write_bytes == 2);
  rewind(output);
  assert(fgetc(output) == 'A' && fgetc(output) == 'B' && fgetc(output) == EOF);
  for (int function = 2; function <= 6; function += 4) {
    set_reg16(uc, UC_X86_REG_AX, function << 8);
    set_reg16(uc, UC_X86_REG_DX, 'X');
    set_reg16(uc, UC_X86_REG_IP, 0x100);
    uint64_t calls = context.engine.metrics.host_write_calls;
    assert(!daze_unicorn_int21_dispatch(uc, &context.engine, &context.run, &context.process, NULL));
    assert(context.engine.metrics.host_write_calls == calls &&
           get_reg16(uc, UC_X86_REG_IP) == 0x100);
  }
  call(uc, &context, &files, 0x0600, 0, 0xff, 0x0600, 0);
  assert(get_reg32(uc, UC_X86_REG_EFLAGS) & 0x40);
  assert(context.engine.metrics.host_write_calls == 2);
  call(uc, &context, &files, 0x0b00, 0, 0, 0x0b00, 0);
  call(uc, &context, &files, 0x5d06, 0, 0, 0x5d06, 0);
  assert(get_reg16(uc, UC_X86_REG_DS) == k_dos_int21_vector_segment);
  call(uc, &context, &files, 0x6700, 20, 0, 0x6700, 0);
  DazeDosInt21Result result = {.register_write_mask = DAZE_DOS_INT21_REG_SI |
                                                      DAZE_DOS_INT21_REG_DI | DAZE_DOS_INT21_REG_DS,
                               .si = 0x1122,
                               .di = 0x3344,
                               .ds = 0x5566};
  assert(apply_int21_result(uc, &result));
  assert(get_reg16(uc, UC_X86_REG_SI) == 0x1122 && get_reg16(uc, UC_X86_REG_DI) == 0x3344 &&
         get_reg16(uc, UC_X86_REG_DS) == 0x5566);
  DazeInt21UnicornPreReleaseContext hook = {
    .uc = uc, .run = &context.run, .engine = &context.engine};
  for (int absent = 0; absent < 4; ++absent) {
    DazeInt21UnicornPreReleaseContext invalid = hook;
    if (absent == 1) invalid.uc = NULL;
    if (absent == 2) invalid.run = NULL;
    if (absent == 3) invalid.engine = NULL;
    assert(!int21_unicorn_pre_release(absent == 0 ? NULL : &invalid, 0x3000));
  }
  assert(int21_unicorn_pre_release(&hook, 0x3000));
  DazeDosInt21Request request = {.ax = 0x3f00, .bx = 5, .cx = 8, .ds = 0x1000, .dx = 0x200};
  DazeDosfsFileResult file = {.byte_count = 4, .host_read_attempted = 1};
  uint64_t reads = context.engine.metrics.host_read_calls;
  uint64_t writes = context.engine.metrics.host_write_calls;
  int21_unicorn_transfer_observed(&hook, &request, &file);
  assert(context.engine.metrics.host_read_calls == reads + 1 &&
         context.engine.metrics.host_write_calls == writes);
  request.ax = 0x4000;
  file.host_read_attempted = 0;
  file.host_write_attempted = 1;
  int21_unicorn_transfer_observed(&hook, &request, &file);
  assert(context.engine.metrics.host_read_calls == reads + 1 &&
         context.engine.metrics.host_write_calls == writes + 1);
  file.host_write_attempted = 0;
  int21_unicorn_transfer_observed(&hook, &request, &file);
  assert(context.engine.metrics.host_read_calls == reads + 1 &&
         context.engine.metrics.host_write_calls == writes + 1);
  request.ax = 0x3f00;
  for (int absent = 0; absent < 4; ++absent) {
    DazeInt21UnicornPreReleaseContext invalid = hook;
    if (absent == 1) invalid.engine = NULL;
    int21_unicorn_transfer_observed(absent == 0 ? NULL : &invalid, absent == 2 ? NULL : &request,
                                    absent == 3 ? NULL : &file);
  }
  FILE *diagnostics = tmpfile();
  assert(diagnostics != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(diagnostics), STDERR_FILENO) >= 0);
  context.engine.debug = 1;
  context.engine.diagnostic_trace.enabled = 1;
  int21_unicorn_transfer_completed(&hook, &request, &file);
  request.ax = 0x4000;
  int21_unicorn_transfer_completed(&hook, &request, &file);
  set_reg16(uc, UC_X86_REG_DS, 0);
  const char message[] = "ok$";
  assert(uc_mem_write(uc, 0x1000, message, sizeof(message)) == UC_ERR_OK);
  call(uc, &context, &files, 0x0900, 0, 0x1000, 0x0900, 0);
  call(uc, &context, &files, 0x3521, 0, 0, 0x3521, 0);
  call(uc, &context, &files, 0x352f, 0, 0, 0x352f, 0);
  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(diagnostics);
  char text[2048] = {0};
  assert(fread(text, 1, sizeof(text) - 1, diagnostics) > 0);
  assert(strstr(text, "read: handle 5, 8 bytes -> 4 bytes at 1000:0200") != NULL);
  assert(strstr(text, "write: handle 5, 4 bytes from") != NULL);
  assert(strstr(text, "display string: ok") != NULL);
  fclose(diagnostics);
  set_reg16(uc, UC_X86_REG_AX, 0x3127);
  assert(daze_unicorn_int21_dispatch(uc, &context.engine, &context.run, &context.process, &files));
  assert(context.run.terminated && context.run.exit_code == 0x27);
  daze_dos_process_state_dispose(&context.process.dos_process);
  daze_dosfs_handles_close_all(&handles);
  fclose(output);
  uc_close(uc);
  return 0;
}
