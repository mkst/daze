#include "dpmi_test_driver.h"
#include "unicorn_services.h"
#include "descriptor.h"
#include "byte_order.h"
#include "dpmi_error.h"
#include "interrupt_vector.h"
#include "rm_frame.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static DazeDosfsMounts mounts;
static DazeDosfsHandles handles;
static DazeDosfsFileService files;

static int dos_call(DazeUnicornDpmiTestDriver *d, uint16_t ax, uint16_t bx, uint16_t cx,
                    uint16_t dx, uint16_t expected, int carry) {
  set_reg16(d->engine, UC_X86_REG_AX, ax);
  set_reg16(d->engine, UC_X86_REG_BX, bx);
  set_reg16(d->engine, UC_X86_REG_CX, cx);
  set_reg16(d->engine, UC_X86_REG_DX, dx);
  set_reg16(d->engine, UC_X86_REG_IP, 0x100);
  set_reg32(d->engine, UC_X86_REG_EFLAGS, 0x203);
  d->context.run.continue_run = 0;
  const int handled = daze_unicorn_int21_dispatch(d->engine, &d->context.engine, &d->context.run,
                                                  &d->context.process, &files);
  const int pass = handled && get_reg16(d->engine, UC_X86_REG_AX) == expected &&
                   (get_reg32(d->engine, UC_X86_REG_EFLAGS) & 1u) == (unsigned)carry &&
                   get_reg16(d->engine, UC_X86_REG_IP) == 0x102 && d->context.run.continue_run;
  if (!pass)
    fprintf(stderr, "DOS %04x reply handled=%d ax=%04x flags=%x ip=%x\n", ax, handled,
            get_reg16(d->engine, UC_X86_REG_AX), get_reg32(d->engine, UC_X86_REG_EFLAGS),
            get_reg16(d->engine, UC_X86_REG_IP));
  return pass;
}

static int dos_matrix(DazeUnicornDpmiTestDriver *d) {
  char root[] = "/tmp/daze-unicorn-adapter-XXXXXX";
  if (mkdtemp(root) == NULL) return 0;
  int root_fd = open(root, O_RDONLY | O_DIRECTORY);
  if (root_fd < 0) {
    rmdir(root);
    return 0;
  }
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  daze_dosfs_mounts_add_named(&mounts, 2, root_fd, 0);
  daze_dos_process_state_init(&d->context.process.dos_process, 0x1000);
  daze_dos_memory_init(&d->context.process.dos_memory, 0x3000, 0xa000);
  set_reg32(d->engine, UC_X86_REG_CR0, 0);
  set_reg16(d->engine, UC_X86_REG_DS, 0x1000);
  set_reg16(d->engine, UC_X86_REG_ES, 0x1000);
  const char name[] = "C:\\DATA.BIN";
  uc_mem_write(d->engine, 0x10100, name, sizeof(name));
  int pass = dos_call(d, 0x3c00, 0, 0, 0x100, 5, 0);
  const uint8_t payload[] = {0x41, 0, 0xff, 0x0a};
  uc_mem_write(d->engine, 0x10200, payload, sizeof(payload));
  pass &= dos_call(d, 0x4000, 5, sizeof(payload), 0x200, sizeof(payload), 0);
  pass &= dos_call(d, 0x4200, 5, 0, 0, 0, 0);
  pass &= dos_call(d, 0x3f00, 5, sizeof(payload), 0x300, sizeof(payload), 0);
  uint8_t after[4];
  uc_mem_read(d->engine, 0x10300, after, sizeof(after));
  pass &= memcmp(after, payload, sizeof(payload)) == 0 &&
          d->context.engine.metrics.host_write_bytes == sizeof(payload) &&
          d->context.engine.metrics.host_read_bytes == sizeof(payload);
  pass &= dos_call(d, 0x4400, 5, 0, 0, 0x4400, 0);
  pass &= dos_call(d, 0x5700, 5, 0, 0, 0x5700, 0);
  pass &= dos_call(d, 0x5701, 5, 0, 0, 0x5701, 0);
  pass &= dos_call(d, 0x4600, 5, 6, 0, 6, 0);
  pass &= dos_call(d, 0x3e00, 6, 0, 0, 0x3e00, 0);
  pass &= dos_call(d, 0x3e00, 5, 0, 0, 0x3e00, 0);
  const uint16_t invalid_handle[] = {0x3e00, 0x3f00, 0x4000, 0x4200, 0x4400, 0x4600, 0x5700};
  for (size_t i = 0; i < sizeof(invalid_handle) / sizeof(invalid_handle[0]); i++)
    pass &= dos_call(d, invalid_handle[i], 99, 4, 0x200, 6, 1);
  pass &= dos_call(d, 0x3d00, 0, 0, 0x100, 5, 0);
  set_reg16(d->engine, UC_X86_REG_DS, 0xffff);
  pass &= uc_mem_unmap(d->engine, 0x10f000, 0x1000) == UC_ERR_OK;
  const DazeDosProcessState saved = d->context.process.dos_process;
  for (int kind = 0; kind < 2; ++kind) {
    set_reg16(d->engine, UC_X86_REG_AX, kind == 0 ? 0x3f00 : 0x3d00);
    set_reg16(d->engine, UC_X86_REG_BX, 5);
    set_reg16(d->engine, UC_X86_REG_CX, 4);
    set_reg16(d->engine, UC_X86_REG_DX, 0xfffe);
    set_reg16(d->engine, UC_X86_REG_IP, 0x100);
    pass &= !daze_unicorn_int21_dispatch(d->engine, &d->context.engine, &d->context.run,
                                         &d->context.process, &files) &&
            get_reg16(d->engine, UC_X86_REG_IP) == 0x100 &&
            memcmp(&saved, &d->context.process.dos_process, sizeof(saved)) == 0;
  }
  pass &= uc_mem_map(d->engine, 0x10f000, 0x1000, UC_PROT_ALL) == UC_ERR_OK;
  set_reg16(d->engine, UC_X86_REG_DS, 0x1000);
  pass &= dos_call(d, 0x3e00, 5, 0, 0, 0x3e00, 0);
  pass &= dos_call(d, 0x1a00, 0, 0, 0x350, 0x1a00, 0);
  pass &= dos_call(d, 0x2f00, 0, 0, 0, 0x2f00, 0) &&
          get_reg16(d->engine, UC_X86_REG_ES) == 0x1000 &&
          get_reg16(d->engine, UC_X86_REG_BX) == 0x350;
  pass &= dos_call(d, 0x2501, 0, 0, 0x456, 0x2501, 0);
  pass &= dos_call(d, 0x3501, 0, 0, 0, 0x3501, 0) &&
          get_reg16(d->engine, UC_X86_REG_ES) == 0x1000 &&
          get_reg16(d->engine, UC_X86_REG_BX) == 0x456;
  pass &= dos_call(d, 0x4301, 0, 0, 0x100, 0x4301, 0);
  set_reg16(d->engine, UC_X86_REG_AX, 0x4302);
  set_reg16(d->engine, UC_X86_REG_IP, 0x100);
  pass &= !daze_unicorn_int21_dispatch(d->engine, &d->context.engine, &d->context.run,
                                       &d->context.process, &files) &&
          get_reg16(d->engine, UC_X86_REG_IP) == 0x100;
  pass &= dos_call(d, 0x4b00, 0, 0, 0x100, 2, 1) && !d->context.process.child_process.active;
  const DazeDosRuntimeProcessState before = d->context.process;
  set_reg16(d->engine, UC_X86_REG_AX, 0xff00);
  set_reg16(d->engine, UC_X86_REG_IP, 0x100);
  pass &= !daze_unicorn_int21_dispatch(d->engine, &d->context.engine, &d->context.run,
                                       &d->context.process, &files) &&
          memcmp(&before, &d->context.process, sizeof(before)) == 0 &&
          get_reg16(d->engine, UC_X86_REG_IP) == 0x100;
  set_reg16(d->engine, UC_X86_REG_AX, 0x4c25);
  pass &= daze_unicorn_int21_dispatch(d->engine, &d->context.engine, &d->context.run,
                                      &d->context.process, &files) &&
          d->context.run.terminated && d->context.run.exit_code == 37 &&
          get_reg16(d->engine, UC_X86_REG_IP) == 0x100;
  daze_dos_process_state_dispose(&d->context.process.dos_process);
  daze_dosfs_handles_close_all(&handles);
  unlinkat(root_fd, "DATA.BIN", 0);
  close(root_fd);
  rmdir(root);
  return pass;
}

static int dpmi_call(DazeUnicornDpmiTestDriver *d, uint16_t ax, uint16_t bx, uint16_t cx,
                     uint16_t dx, uint16_t di, uint16_t expected, int carry) {
  set_reg16(d->engine, UC_X86_REG_IP, 0x100);
  DazeUnicornDpmiTestSnapshot s;
  const int ran = daze_unicorn_dpmi_test_driver_run(
    d,
    &(DazeUnicornDpmiTestInput){
      .eax = 0xa5a50000u | ax, .ebx = bx, .ecx = cx, .edx = dx, .edi = di, .eflags = 0x202},
    &s);
  const int pass = ran && s.eax == (0xa5a50000u | expected) && (s.eflags & 1) == (unsigned)carry &&
                   (s.eflags & 0x200) && get_reg16(d->engine, UC_X86_REG_IP) == 0x102;
  if (!pass)
    fprintf(stderr, "DPMI %04x reply ran=%d eax=%x flags=%x ip=%x\n", ax, ran, s.eax, s.eflags,
            get_reg16(d->engine, UC_X86_REG_IP));
  return pass;
}

static int dpmi_matrix(DazeUnicornDpmiTestDriver *d) {
  set_reg32(d->engine, UC_X86_REG_CR0, 0);
  daze_dpmi_linear_memory_init(&d->context.process.dpmi.linear_memory, 0x20000, 0x30000);
  int pass = dpmi_call(d, 0x0501, 0, 0x2000, 0, 0, 0x0501, 0);
  pass &= get_reg16(d->engine, UC_X86_REG_BX) == 2 && get_reg16(d->engine, UC_X86_REG_CX) == 0 &&
          get_reg16(d->engine, UC_X86_REG_DI) == 1;
  pass &= dpmi_call(d, 0x0503, 0, 0x3000, 0, 1, 0x0503, 0);
  pass &= dpmi_call(d, 0x0502, 0, 0, 0, 1, 0x0502, 0);
  const DazeDpmiLinearMemory before = d->context.process.dpmi.linear_memory;
  pass &= dpmi_call(d, 0x0502, 0, 0, 0, 1, 0x8023, 1) &&
          memcmp(&before, &d->context.process.dpmi.linear_memory, sizeof(before)) == 0;
  pass &= dpmi_call(d, 0x0501, 0, 0, 0, 0, 0x8012, 1);
  pass &= dpmi_call(d, 0x0202, 32, 0, 0, 0, 0x8021, 1);
  pass &= dpmi_call(d, 0x0203, 32, 0, 0, 0, 0x8021, 1);
  const uint16_t bad_selector[] = {0x0001, 0x0006, 0x0007, 0x0009, 0x000b, 0x000c};
  for (size_t i = 0; i < sizeof(bad_selector) / sizeof(bad_selector[0]); ++i)
    pass &= dpmi_call(d, bad_selector[i], 0xffff, 0, 0, 0x200, 0x8022, 1);
  pass &= dpmi_call(d, 0x0008, 0xffff, 0, 0, 0, 0x8021, 1);
  pass &= dpmi_call(d, 0x0000, 0, 1, 0, 0, 0x84, 0);
  const uint16_t selector = 0x84;
  pass &= dpmi_call(d, 0x0007, selector, 0x1234, 0x5678, 0, 0x0007, 0);
  pass &= dpmi_call(d, 0x0006, selector, 0, 0, 0, 0x0006, 0) &&
          get_reg16(d->engine, UC_X86_REG_CX) == 0x1234 &&
          get_reg16(d->engine, UC_X86_REG_DX) == 0x5678;
  uint8_t descriptor[8], after[8];
  uc_mem_read(d->engine, k_dpmi_ldt_address + 0x80, descriptor, 8);
  pass &= dpmi_call(d, 0x0008, selector, 0x10, 0, 0, 0x8021, 1);
  pass &= dpmi_call(d, 0x0009, selector, 0x98, 0, 0, 0x8021, 1);
  uc_mem_read(d->engine, k_dpmi_ldt_address + 0x80, after, 8);
  pass &= memcmp(descriptor, after, 8) == 0;
  pass &= dpmi_call(d, 0x000b, selector, 0, 0, 0x200, 0x000b, 0);
  uc_mem_read(d->engine, 0x200, after, 8);
  pass &= memcmp(descriptor, after, 8) == 0;
  daze_dpmi_descriptor_encode(after, 0x26000, 0xffff, 0x92, 0);
  uc_mem_write(d->engine, 0x200, after, 8);
  pass &= dpmi_call(d, 0x000c, selector, 0, 0, 0x200, 0x000c, 0);
  uc_mem_read(d->engine, k_dpmi_ldt_address + 0x80, descriptor, 8);
  pass &= memcmp(descriptor, after, 8) == 0;
  pass &= dpmi_call(d, 0x0001, selector, 0, 0, 0, 0x0001, 0);
  pass &= dpmi_call(d, 0x0000, 0, 0, 0, 0, 0x8011, 1);
  d->context.process.dpmi.virtual_interrupts_enabled = 1;
  pass &= dpmi_call(d, 0x0900, 0, 0, 0, 0, 0x0901, 0) &&
          !d->context.process.dpmi.virtual_interrupts_enabled;
  pass &= dpmi_call(d, 0x0901, 0, 0, 0, 0, 0x0900, 0) &&
          d->context.process.dpmi.virtual_interrupts_enabled;
  set_reg16(d->engine, UC_X86_REG_AX, 0xffff);
  const DazeDpmiProcessState state = d->context.process.dpmi;
  pass &=
    !daze_int31_dispatch(d->engine, &d->context.engine, &d->context.run, &d->context.process) &&
    memcmp(&state, &d->context.process.dpmi, sizeof(state)) == 0;
  return pass;
}

static int guest_memory_contract(DazeUnicornDpmiTestDriver *d) {
  uint8_t descriptor[8];
  daze_dpmi_descriptor_encode(descriptor, 0x12340, 0xffff, 0x92, 0);
  uc_mem_write(d->engine, k_dpmi_gdt_address + 0x10, descriptor, 8);
  set_reg32(d->engine, UC_X86_REG_CR0, 1);
  const char message[] = "bounded";
  char output[16];
  int pass = daze_write_guest_bytes(d->engine, 0x10, 0x20, message, sizeof(message)) &&
             daze_read_guest_asciiz(d->engine, 0x10, 0x20, output, sizeof(output)) &&
             strcmp(output, message) == 0;
  output[0] = '!';
  pass &= !daze_read_guest_asciiz(d->engine, 0x10, 0x20, output, 4) && output[0] == 0;
  pass &= !daze_read_guest_bytes(d->engine, 0, 0, output, 1);
  daze_dpmi_descriptor_encode(descriptor, UINT32_MAX - 4, 0xffff, 0x92, 0);
  uc_mem_write(d->engine, k_dpmi_gdt_address + 0x10, descriptor, 8);
  pass &= !daze_read_guest_bytes(d->engine, 0x10, 8, output, 1) &&
          !daze_write_guest_bytes(d->engine, 0x10, 0, message, sizeof(message));
  return pass;
}

static int runtime_boundaries(DazeUnicornDpmiTestDriver *d) {
  uint8_t code[8], data[8];
  daze_dpmi_descriptor_encode(code, 0x15000, 0xffff, 0x9a, 0);
  daze_dpmi_descriptor_encode(data, 0x26000, 0xffff, 0x92, 0);
  uc_mem_write(d->engine, k_dpmi_gdt_address + 8, code, 8);
  uc_mem_write(d->engine, k_dpmi_gdt_address + 0x10, data, 8);
  const uc_x86_mmr gdtr = {.base = k_dpmi_gdt_address, .limit = 0x1f};
  if (uc_reg_write(d->engine, UC_X86_REG_GDTR, &gdtr) != UC_ERR_OK) return 0;
  set_reg32(d->engine, UC_X86_REG_CR0, 1);
  set_reg16(d->engine, UC_X86_REG_CS, 8);
  set_reg16(d->engine, UC_X86_REG_SS, 0x10);
  set_reg32(d->engine, UC_X86_REG_ESP, 0x100);
  set_reg16(d->engine, UC_X86_REG_ES, 0x10);
  const DpmiAlternateState state = {.eax = 0x12345678,
                                    .esp = 0x100,
                                    .eip = 0x20,
                                    .cs = 0x1234,
                                    .ds = 0x1000,
                                    .ss = 0x1800,
                                    .eflags = 2};
  d->context.process.dpmi.real_mode_state = state;
  d->context.process.dpmi.real_mode_state_valid = 1;
  d->context.engine.metrics.enabled = 1;
  set_reg16(d->engine, UC_X86_REG_AX, 0);
  set_reg32(d->engine, UC_X86_REG_EDI, 0x200);
  set_reg16(d->engine, UC_X86_REG_IP, 0x100);
  int pass = daze_dispatch_interrupt(d->engine, DAZE_INT_STATE_SAVE_GATE, &d->context.engine,
                                     &d->context.run, &d->context.process, &files);
  DpmiAlternateState got;
  uc_mem_read(d->engine, 0x26200, &got, sizeof(got));
  pass &= memcmp(&got, &state, sizeof(got)) == 0 && get_reg16(d->engine, UC_X86_REG_IP) == 0x102;
  got.eax = 0x87654321;
  uc_mem_write(d->engine, 0x26200, &got, sizeof(got));
  set_reg16(d->engine, UC_X86_REG_AX, 1);
  pass &= daze_dispatch_interrupt(d->engine, DAZE_INT_STATE_SAVE_GATE, &d->context.engine,
                                  &d->context.run, &d->context.process, &files) &&
          d->context.process.dpmi.real_mode_state.eax == 0x87654321 &&
          get_reg32(d->engine, UC_X86_REG_CR0) == 1;
  set_reg16(d->engine, UC_X86_REG_AX, 2);
  pass &= daze_dispatch_interrupt(d->engine, DAZE_INT_STATE_SAVE_GATE, &d->context.engine,
                                  &d->context.run, &d->context.process, &files) &&
          d->context.process.dpmi.real_mode_state.eax == 0x87654321;
  const uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE] = {0};
  uc_mem_write(d->engine, 0x26200, frame, sizeof(frame));
  for (int kind = 0; kind < 4; ++kind) {
    set_reg16(d->engine, UC_X86_REG_AX, kind & 1 ? 0x0301 : 0x0300);
    set_reg16(d->engine, UC_X86_REG_BX, 0x0121);
    set_reg16(d->engine, UC_X86_REG_CX, 0);
    set_reg32(d->engine, UC_X86_REG_EDI, kind < 2 ? 0x200 : UINT32_MAX);
    set_reg16(d->engine, UC_X86_REG_IP, 0x100);
    const DazeDosRuntimeProcessState before = d->context.process;
    pass &= daze_dispatch_interrupt(d->engine, DAZE_INT_DPMI, &d->context.engine, &d->context.run,
                                    &d->context.process, &files) &&
            get_reg16(d->engine, UC_X86_REG_AX) == 0x8021 &&
            (get_reg32(d->engine, UC_X86_REG_EFLAGS) & 1) && !d->context.run.rm_procedure_active &&
            memcmp(&before, &d->context.process, sizeof(before)) == 0;
  }
  pass &= d->context.engine.metrics.interrupt_handler_counts[DAZE_INT_STATE_SAVE_GATE] == 3 &&
          d->context.engine.metrics.interrupt_handler_counts[DAZE_INT_DPMI] == 4;
  set_reg32(d->engine, UC_X86_REG_CR0, 0);
  d->context.run.interrupt_already_advanced = 1;
  set_reg16(d->engine, UC_X86_REG_IP, 0x100);
  set_reg16(d->engine, UC_X86_REG_AX, 0x4c00);
  pass &= daze_dispatch_interrupt(d->engine, DAZE_INT_DOS, &d->context.engine, &d->context.run,
                                  &d->context.process, &files) &&
          d->context.run.terminated && d->context.run.exit_code == 0 &&
          get_reg16(d->engine, UC_X86_REG_IP) == 0x100;
  return pass;
}

int main(void) {
  DazeUnicornDpmiTestDriver d;
  if (!daze_unicorn_dpmi_test_driver_init(&d)) return 1;
  int pass = uc_mem_map(d.engine, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK;
  if (pass) {
    int a = dos_matrix(&d), b = dpmi_matrix(&d), c = guest_memory_contract(&d),
        e = runtime_boundaries(&d);
    pass = a && b && c && e;
    if (!pass) fprintf(stderr, "adapter matrix DOS=%d DPMI=%d memory=%d runtime=%d\n", a, b, c, e);
  }
  daze_unicorn_dpmi_test_driver_destroy(&d);
  return pass ? 0 : 1;
}
