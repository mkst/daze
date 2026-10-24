#include "unicorn_services.h"
#include "byte_order.h"
#include "descriptor.h"
#include "interrupt_vector.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
  do {                                                                                             \
    if (!(condition)) {                                                                            \
      fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition);                              \
      pass = 0;                                                                                    \
      goto out;                                                                                    \
    }                                                                                              \
  } while (0)

static int exec_case(int kind) {
  int pass = 1;
  char root[] = "/tmp/daze-unicorn-startup-XXXXXX";
  if (mkdtemp(root) == NULL) return 0;
  int root_fd = open(root, O_RDONLY | O_DIRECTORY);
  if (root_fd < 0) {
    rmdir(root);
    return 0;
  }
  uc_engine *uc = NULL;
  DazeUnicornContext context = {0};
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  daze_dosfs_mounts_add_named(&mounts, 2, root_fd, 0);
  uint8_t image[64] = {'M', 'Z'};
  daze_write_u16(image + 2, sizeof(image));
  daze_write_u16(image + 4, 1);
  daze_write_u16(image + 8, 2);
  daze_write_u16(image + 0x10, 0x100);
  daze_write_u16(image + 0x18, 0x1c);
  const uint8_t code[] = {
    0xb8, 0x25, 0x4c, /* mov ax,0x4c25 */
    0xcd, 0x21,       /* int 0x21 */
  };
  memcpy(image + 32, code, sizeof(code));
  if (kind == 2) image[0] = 'X';
  if (kind == 11) {
    daze_write_u16(image + 6, 1);
    daze_write_u16(image + 0x1c, 0xffff);
  }
  if (kind == 17) daze_write_u16(image + 4, 2049);
  int fd = openat(root_fd, "CHILD.EXE", O_WRONLY | O_CREAT | O_EXCL, 0600);
  CHECK(fd >= 0);
  int wrote = write(fd, image, sizeof(image)) == sizeof(image);
  if (kind == 17) wrote &= ftruncate(fd, 2048 * 512 + sizeof(image)) == 0;
  close(fd);
  CHECK(wrote);
  CHECK(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  CHECK(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  daze_dos_process_state_init(&context.process.dos_process, 0x1000);
  daze_dos_process_state_set_dta(&context.process.dos_process, 0x1234, 0x4567);
  daze_dos_memory_init(&context.process.dos_memory, 0x3000, kind == 3 ? 0x3001 : 0xa000);
  context.process.resident_image_end = 0x20000;
  context.engine.debug = kind == 0;
  context.engine.metrics.enabled = 1;
  set_reg16(uc, UC_X86_REG_CS, 0x1000);
  set_reg16(uc, UC_X86_REG_IP, 0x100);
  set_reg16(uc, UC_X86_REG_SS, 0x1000);
  set_reg16(uc, UC_X86_REG_SP, 0x800);
  set_reg16(uc, UC_X86_REG_DS, 0x1000);
  set_reg16(uc, UC_X86_REG_ES, 0x1000);
  set_reg16(uc, UC_X86_REG_AX, 0x4b00);
  set_reg16(uc, UC_X86_REG_DX, 0x200);
  set_reg16(uc, UC_X86_REG_BX, 0x300);
  uint8_t parameter[14] = {0};
  daze_write_u16(parameter, 0x2000);
  for (int i = 0; i < 3; ++i) {
    daze_write_u16(parameter + 2 + 4 * i, (uint16_t)(0x400 + 0x100 * i));
    daze_write_u16(parameter + 4 + 4 * i, 0x1000);
  }
  uint8_t tail[127] = {2, ' ', 'x'};
  const uint8_t fcb[16] = {0, 'F', 'I', 'L', 'E'};
  const char *path = kind == 1 ? "MISSING.EXE" : "CHILD.EXE";
  CHECK(uc_mem_write(uc, 0x10200, path, strlen(path) + 1) == UC_ERR_OK);
  CHECK(uc_mem_write(uc, 0x10300, parameter, sizeof(parameter)) == UC_ERR_OK);
  CHECK(uc_mem_write(uc, 0x10400, tail, sizeof(tail)) == UC_ERR_OK);
  CHECK(uc_mem_write(uc, 0x10500, fcb, sizeof(fcb)) == UC_ERR_OK);
  CHECK(uc_mem_write(uc, 0x10600, fcb, sizeof(fcb)) == UC_ERR_OK);
  if (kind == 4) CHECK(uc_mem_unmap(uc, 0x30000, 0x1000) == UC_ERR_OK);
  if (kind == 5) CHECK(uc_mem_unmap(uc, 0x2000, 0x1000) == UC_ERR_OK);
  if (kind == 6) tail[0] = 127;
  if (kind == 6) CHECK(uc_mem_write(uc, 0x10400, tail, sizeof(tail)) == UC_ERR_OK);
  if (kind == 7) set_reg32(uc, UC_X86_REG_CR0, 1);
  if (kind == 8) set_reg16(uc, UC_X86_REG_AX, 0x4b01);
  if (kind == 9) context.process.child_process.active = 1;
  if (kind == 10) {
    handles.host_fds[5] = dup(root_fd);
    CHECK(handles.host_fds[5] >= 0);
    close(handles.host_fds[5]);
  }
  if (kind >= 12 && kind <= 16) {
    CHECK(uc_mem_unmap(uc, 0x10f000, 0x1000) == UC_ERR_OK);
    if (kind == 12) {
      set_reg16(uc, UC_X86_REG_DS, 0xffff);
      set_reg16(uc, UC_X86_REG_DX, 0xffff);
    } else if (kind == 13) {
      set_reg16(uc, UC_X86_REG_ES, 0xffff);
      set_reg16(uc, UC_X86_REG_BX, 0xffff);
    } else {
      size_t slot = 2 + (size_t)(kind - 14) * 4;
      daze_write_u16(parameter + slot, 0xffff);
      daze_write_u16(parameter + slot + 2, 0xffff);
      CHECK(uc_mem_write(uc, 0x10300, parameter, sizeof(parameter)) == UC_ERR_OK);
    }
  }
  const DazeDosMemory memory = context.process.dos_memory;
  char diagnostic[256] = {0};
  int started = daze_setup_start_exec_child(uc, &context.engine, &context.run, &context.process,
                                            &files, diagnostic, sizeof(diagnostic));
  if (kind != 0 && kind != 18) {
    CHECK(!started && diagnostic[0] != 0 && context.process.child_process.parent_context == NULL);
    CHECK(memcmp(&memory, &context.process.dos_memory, sizeof(memory)) == 0);
    CHECK(context.process.dos_process.psp_segment == 0x1000);
    CHECK(context.process.dos_process.dta_segment == 0x1234);
    CHECK(get_reg16(uc, UC_X86_REG_IP) == 0x100 && !context.run.use_resume_address);
    context.process.child_process.active = 0;
  } else {
    CHECK(started && context.process.child_process.active);
    CHECK(context.process.child_process.parent_context != NULL);
    uint8_t psp[256], loaded[sizeof(code)];
    CHECK(uc_mem_read(uc, 0x30000, psp, sizeof(psp)) == UC_ERR_OK);
    CHECK(psp[0] == 0xcd && psp[1] == 0x20 && daze_read_u16(psp + 0x16) == 0x1000);
    CHECK(daze_read_u16(psp + 0x2c) == 0x2000 && psp[0x80] == 2 && psp[0x82] == 'x');
    CHECK(memcmp(psp + 0x5c, fcb, sizeof(fcb)) == 0);
    CHECK(uc_mem_read(uc, 0x30100, loaded, sizeof(loaded)) == UC_ERR_OK);
    CHECK(memcmp(loaded, code, sizeof(code)) == 0);
    CHECK(context.run.use_resume_address && context.run.resume_address == 0x30100);
    CHECK(get_reg16(uc, UC_X86_REG_DS) == 0x3000 && get_reg16(uc, UC_X86_REG_SP) == 0x100);
    set_reg16(uc, UC_X86_REG_AX, kind == 18 ? 0x3125 : 0x4c25);
    const DazeDosMemory child_memory = context.process.dos_memory;
    CHECK(daze_unicorn_int21_dispatch(uc, &context.engine, &context.run, &context.process, &files));
    CHECK(!context.process.child_process.active &&
          context.process.child_process.parent_context == NULL);
    CHECK(context.process.child_process.status_available &&
          context.process.child_process.exit_code == 0x25);
    CHECK(context.process.dos_process.psp_segment == 0x1000 &&
          context.process.dos_process.dta_offset == 0x4567);
    CHECK(context.process.resident_image_end == 0x20000 &&
          memcmp(kind == 18 ? &child_memory : &memory, &context.process.dos_memory,
                 sizeof(memory)) == 0);
    CHECK(get_reg16(uc, UC_X86_REG_CS) == 0x1000 && get_reg16(uc, UC_X86_REG_IP) == 0x100);
    set_reg16(uc, UC_X86_REG_AX, 0x4d00);
    CHECK(daze_unicorn_int21_dispatch(uc, &context.engine, &context.run, &context.process, &files));
    CHECK(get_reg16(uc, UC_X86_REG_AX) == (kind == 18 ? 0x325 : 0x25) &&
          !context.process.dos_process.child_status_available);
  }
out:
  if (context.process.child_process.parent_context != NULL)
    uc_context_free(context.process.child_process.parent_context);
  daze_dosfs_exec_handles_restore(&context.process.child_process.handles);
  daze_dos_process_state_dispose(&context.process.dos_process);
  daze_dosfs_handles_close_all(&handles);
  if (uc != NULL) uc_close(uc);
  unlinkat(root_fd, "CHILD.EXE", 0);
  close(root_fd);
  rmdir(root);
  return pass;
}

static int procedure_case(int interrupt, int kind) {
  int pass = 1;
  uc_engine *uc = NULL;
  DazeUnicornContext context = {0};
  CHECK(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  CHECK(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  uint8_t descriptor[8];
  daze_dpmi_descriptor_encode(descriptor, 0x10000, 0xffff, 0x9a, kind == 6 ? 0x04 : 0);
  CHECK(uc_mem_write(uc, k_dpmi_gdt_address + 8, descriptor, 8) == UC_ERR_OK);
  daze_dpmi_descriptor_encode(descriptor, 0x20000, 0xffff, 0x92, 0);
  CHECK(uc_mem_write(uc, k_dpmi_gdt_address + 0x10, descriptor, 8) == UC_ERR_OK);
  daze_dpmi_descriptor_encode(descriptor, 0x280, 0xffff, 0x9a, 0);
  CHECK(uc_mem_write(uc, k_dpmi_gdt_address + 0x28, descriptor, 8) == UC_ERR_OK);
  uc_x86_mmr gdtr = {.base = k_dpmi_gdt_address, .limit = 0x2f};
  CHECK(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) == UC_ERR_OK);
  set_reg32(uc, UC_X86_REG_CR0, 1);
  set_reg16(uc, UC_X86_REG_CS, 8);
  set_reg16(uc, UC_X86_REG_SS, 0x10);
  set_reg16(uc, UC_X86_REG_ES, 0x10);
  set_reg16(uc, UC_X86_REG_DS, 0x10);
  set_reg32(uc, UC_X86_REG_ESP, kind == 7 ? 0x10000 : kind == 17 ? 0x1800 : 0x800);
  set_reg32(uc, UC_X86_REG_EIP, kind == 8 ? 0x10000 : 0x100);
  set_reg16(uc, UC_X86_REG_AX, interrupt ? 0x0300 : 0x0301);
  set_reg16(uc, UC_X86_REG_BX, kind == 4 ? 0x0121 : 0x21);
  const uint16_t parameter_words = kind == 22 || kind == 23                  ? 3
                                   : kind == 2 || (kind >= 16 && kind <= 18) ? 2
                                                                             : 0;
  set_reg16(uc, UC_X86_REG_CX, parameter_words);
  set_reg32(uc, UC_X86_REG_EDI, kind == 3 ? UINT32_MAX : 0x200);
  uint8_t frame[k_dpmi_rm_frame_size] = {0};
  const uint8_t reserved[] = {0xde, 0xad, 0xbe, 0xef};
  memcpy(frame + 0x0c, reserved, sizeof(reserved));
  daze_write_u32(frame + k_dpmi_rm_eax, 0x12345678);
  daze_write_u32(frame + k_dpmi_rm_ebx, 0x87654321);
  daze_write_u16(frame + k_dpmi_rm_cs, kind == 5 ? 0 : 0x3000);
  daze_write_u16(frame + k_dpmi_rm_ip, 0x400);
  daze_write_u16(frame + k_dpmi_rm_flags, 0x203);
  if (kind == 1 || kind == 2 || kind == 9 || kind == 22) {
    daze_write_u16(frame + k_dpmi_rm_ss, 0x4000);
    daze_write_u16(frame + k_dpmi_rm_sp, kind == 9 ? 3 : 0x800);
  }
  if (kind == 13) daze_write_u16(frame + k_dpmi_rm_sp, 0x100);
  if (kind == 15 || kind == 18) {
    daze_write_u16(frame + k_dpmi_rm_ss, 0x4000);
    daze_write_u16(frame + k_dpmi_rm_sp, kind == 18 ? 0x1000 : 0x800);
  }
  const uint16_t parameters[] = {0x1234, 0x5678, 0x9abc};
  CHECK(uc_mem_write(uc, 0x20800, parameters, sizeof(parameters)) == UC_ERR_OK);
  CHECK(uc_mem_write(uc, 0x20200, frame, sizeof(frame)) == UC_ERR_OK);
  if (kind == 10) set_reg16(uc, UC_X86_REG_ES, 0);
  if (kind == 11 || kind == 16) {
    daze_dpmi_descriptor_encode(descriptor, k_memory_size - 16, 0xffff, 0x92, 0);
    CHECK(uc_mem_write(uc, k_dpmi_gdt_address + 0x10, descriptor, 8) == UC_ERR_OK);
    if (kind == 16) {
      daze_dpmi_descriptor_encode(descriptor, 0x20000, 0xffff, 0x92, 0);
      CHECK(uc_mem_write(uc, k_dpmi_gdt_address + 0x18, descriptor, 8) == UC_ERR_OK);
      set_reg16(uc, UC_X86_REG_ES, 0x18);
    }
  }
  if (kind == 12) CHECK(uc_mem_unmap(uc, 0x20000, 0x1000) == UC_ERR_OK);
  if (kind == 14) CHECK(uc_mem_unmap(uc, 0x2000, 0x1000) == UC_ERR_OK);
  if (kind == 15) CHECK(uc_mem_unmap(uc, 0x40000, 0x1000) == UC_ERR_OK);
  if (kind == 17) CHECK(uc_mem_unmap(uc, 0x21000, 0x1000) == UC_ERR_OK);
  if (kind == 18) CHECK(uc_mem_unmap(uc, 0x41000, 0x1000) == UC_ERR_OK);
  context.process.dos_process.dos_vector_segment[0x21] = kind == 5 ? 0 : 0x3000;
  context.process.dos_process.dos_vector_offset[0x21] = 0x400;
  context.engine.metrics.enabled = 1;
  int accepted = interrupt ? daze_setup_start_dpmi_rm_interrupt(uc, &context.engine, &context.run,
                                                                &context.process)
                           : daze_setup_start_dpmi_rm_procedure(uc, &context.engine, &context.run);
  if (kind == 14 || kind == 15 || (!interrupt && kind >= 16 && kind <= 18)) {
    CHECK(!accepted && !context.run.rm_procedure_active);
    goto out;
  }
  CHECK(accepted);
  const int success =
    (kind < 3 || kind == 13 || kind >= 19) && !(interrupt && parameter_words != 0);
  if (!success && !(interrupt && (kind == 6 || kind == 7 || kind == 8))) {
    CHECK(!context.run.rm_procedure_active && get_reg16(uc, UC_X86_REG_AX) == 0x8021);
    CHECK(get_reg32(uc, UC_X86_REG_EFLAGS) & 1u);
    uint8_t unchanged[sizeof(frame)];
    if (kind != 12) {
      CHECK(uc_mem_read(uc, 0x20200, unchanged, sizeof(unchanged)) == UC_ERR_OK);
      CHECK(memcmp(frame, unchanged, sizeof(frame)) == 0);
    }
    goto out;
  }
  CHECK(context.run.rm_procedure_active && context.run.rm_procedure_frame_address == 0x20200);
  CHECK(context.run.resume_address == 0x3c0 && context.run.use_resume_address);
  CHECK(get_reg32(uc, UC_X86_REG_EAX) == 0x12345678 && get_reg32(uc, UC_X86_REG_EBX) == 0x87654321);
  if (kind == 19 || kind == 20) {
    CHECK(uc_mem_unmap(uc, kind == 19 ? 0x20000 : 0x2000, 0x1000) == UC_ERR_OK);
    CHECK(!daze_setup_complete_dpmi_rm_procedure(uc, &context.engine, &context.run));
    CHECK(context.run.rm_procedure_active);
    goto out;
  }
  uint8_t target[4], stack[10];
  CHECK(uc_mem_read(uc, k_dpmi_rm_target_linear, target, sizeof(target)) == UC_ERR_OK);
  CHECK(daze_read_u16(target) == 0x400 && daze_read_u16(target + 2) == 0x3000);
  uint32_t stack_address =
    kind == 13 ? 0x100 - (interrupt ? 6 : 4)
    : kind == 1 || kind == 2 || kind == 22
      ? 0x40800 - (interrupt ? 6 : 4)
      : ((uint32_t)k_dpmi_return_stack_segment << 4) + k_dpmi_return_stack_sp - (interrupt ? 6 : 0);
  CHECK(uc_mem_read(uc, stack_address, stack, sizeof(stack)) == UC_ERR_OK);
  CHECK(daze_read_u16(stack) == 0 && daze_read_u16(stack + 2) == k_dpmi_rm_gate_segment);
  if (interrupt) CHECK(daze_read_u16(stack + 4) == 0x203);
  if (!interrupt && parameter_words != 0)
    CHECK(memcmp(stack + 4, parameters, parameter_words * 2u) == 0);
  uint8_t expected[sizeof(frame)];
  memcpy(expected, frame, sizeof(expected));
  const uint8_t returned[] = {
    0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xcc, 0xbb, 0xaa, 0x99, 0xde, 0xad,
    0xbe, 0xef, 0x40, 0x30, 0x20, 0x10, 0x01, 0xef, 0xcd, 0xab, 0x80, 0x70, 0x60, 0x50,
    0xba, 0xdc, 0xcd, 0xab, 0xd7, 0x0a, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44,
  };
  memcpy(expected, returned, sizeof(returned));
  set_reg32(uc, UC_X86_REG_CR0, 0);
  set_reg32(uc, UC_X86_REG_EDI, 0x11223344);
  set_reg32(uc, UC_X86_REG_ESI, 0x55667788);
  set_reg32(uc, UC_X86_REG_EBP, 0x99aabbcc);
  set_reg32(uc, UC_X86_REG_EBX, 0x10203040);
  set_reg32(uc, UC_X86_REG_EDX, 0xabcdef01);
  set_reg32(uc, UC_X86_REG_ECX, 0x50607080);
  set_reg32(uc, UC_X86_REG_EAX, 0xabcddcba);
  set_reg32(uc, UC_X86_REG_EFLAGS, 0x0ad7);
  set_reg16(uc, UC_X86_REG_ES, 0x1111);
  set_reg16(uc, UC_X86_REG_DS, 0x2222);
  set_reg16(uc, UC_X86_REG_FS, 0x3333);
  set_reg16(uc, UC_X86_REG_GS, 0x4444);
  CHECK(daze_setup_complete_dpmi_rm_procedure(uc, &context.engine, &context.run));
  CHECK(!context.run.rm_procedure_active && !context.run.rm_procedure_32bit_reentry);
  CHECK(context.run.resume_address == k_dpmi_rm_gate_linear);
  CHECK(uc_mem_read(uc, 0x20200, frame, sizeof(frame)) == UC_ERR_OK);
  CHECK(memcmp(frame, expected, sizeof(frame)) == 0);
  uint8_t saved[0x36];
  CHECK(uc_mem_read(uc, interrupt ? k_pm_reentry32_state : k_pm_reentry_state, saved,
                    interrupt ? 0x36 : 32) == UC_ERR_OK);
  CHECK((interrupt ? daze_read_u32(saved + 0x2c) : daze_read_u16(saved + 0x1a)) ==
        (context.run.rm_procedure_pm_state.eflags & ~1u));
out:
  if (uc != NULL) uc_close(uc);
  return pass;
}

static int raw_vectors_case(int kind) {
  int pass = 1;
  uc_engine *uc = NULL;
  DazeUnicornContext context = {0};
  CHECK(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  CHECK(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  daze_dos_memory_init(&context.process.dos_memory, 0x3000, 0xa000);
  DazeDosAllocation *allocation = daze_dos_memory_allocate(&context.process.dos_memory, 0x100);
  CHECK(allocation != NULL && allocation->segment == 0x3000);
  context.process.child_process.active = 1;
  context.process.child_process.allocation_segment = 0x3000;
  context.run.raw_vector_snapshot_valid = kind != 7;
  context.run.raw_vector_snapshot_child_active = kind != 6;
  context.run.raw_vector_snapshot_allocation_segment = 0x3000;
  context.process.dos_process.dos_vector_segment[0x40] = kind == 5 ? 0x2004 : 0x3004;
  context.process.dos_process.dos_vector_offset[0x40] = 0x20;
  context.process.dos_process.dos_vector_segment[0x41] = 0x3004;
  context.process.dos_process.dos_vector_offset[0x41] = 0x30;
  if (kind == 1) {
    uint8_t existing[8];
    daze_dpmi_descriptor_encode(existing, 0x123456, 0x7777, 0x92, 0);
    CHECK(uc_mem_write(uc, k_dpmi_ldt_address + 0x3000, existing, 8) == UC_ERR_OK);
  }
  if (kind == 2) {
    for (size_t i = 0; i < DAZE_RAW_VECTOR_PROJECTION_MAX; ++i)
      context.run.raw_vector_projections[i] =
        (DazeRawVectorProjection){.selector = (uint16_t)(0x3044 + i * 8),
                                  .allocation_segment = 0x3000,
                                  .allocation_paragraphs = 0x100,
                                  .in_use = 1};
    for (size_t i = 0; i < DAZE_RAW_VECTOR_PROJECTION_MAX; ++i)
      context.process.dos_process.dos_vector_segment[0x50 + i] =
        context.run.raw_vector_projections[i].selector;
  }
  if (kind == 3 || kind == 4 || kind == 7) {
    context.run.raw_vector_projections[0] =
      (DazeRawVectorProjection){.selector = 0x300c,
                                .allocation_segment = 0x3000,
                                .allocation_paragraphs = kind == 4 ? 0x101 : 0x100,
                                .in_use = 1};
    uint8_t old[8];
    daze_dpmi_descriptor_encode(old, 0x300c0, 0xf3f, 0xf2, 0);
    CHECK(uc_mem_write(uc, k_dpmi_ldt_address + 0x3008, old, 8) == UC_ERR_OK);
    if (kind == 4) context.process.dos_process.dos_vector_segment[0x42] = 0x300c;
  }
  context.engine.debug = 1;
  set_reg16(uc, UC_X86_REG_AX, 0x10);
  set_reg16(uc, UC_X86_REG_CX, 0x10);
  set_reg16(uc, UC_X86_REG_DX, 0x10);
  set_reg16(uc, UC_X86_REG_BX, 0x800);
  set_reg16(uc, UC_X86_REG_SI, 8);
  set_reg16(uc, UC_X86_REG_DI, 0x200);
  CHECK(daze_dispatch_interrupt(uc, DAZE_INT_RAW_SWITCH_GATE, &context.engine, &context.run,
                                &context.process, NULL));
  CHECK(context.process.dpmi.real_mode_state_valid && !context.run.raw_vector_snapshot_valid);
  CHECK(context.run.resume_address == ((uint32_t)k_dpmi_entry_segment << 4) + 0x122);
  uint8_t got[8], expected[8] = {0};
  CHECK(uc_mem_read(uc, k_dpmi_ldt_address + 0x3000, got, 8) == UC_ERR_OK);
  if (kind == 1)
    daze_dpmi_descriptor_encode(expected, 0x123456, 0x7777, 0x92, 0);
  else if (kind == 0 || kind == 3 || kind == 4 || kind == 5)
    daze_dpmi_descriptor_encode(expected, 0x30040, 0xfbf, 0xf2, 0);
  CHECK(memcmp(got, expected, 8) == 0);
  if (kind == 3 || kind == 4 || kind == 7) {
    CHECK(uc_mem_read(uc, k_dpmi_ldt_address + 0x3008, got, 8) == UC_ERR_OK);
    if (kind == 4) {
      daze_dpmi_descriptor_encode(expected, 0x300c0, 0xf3f, 0xf2, 0);
      CHECK(memcmp(got, expected, 8) == 0);
    } else
      CHECK(memcmp(got, (uint8_t[8]){0}, 8) == 0);
  }
  CHECK(daze_withdraw_raw_vector_projections(uc, &context.run, &context.engine.metrics, 0x3000));
  CHECK(daze_withdraw_raw_vector_projections(uc, &context.run, &context.engine.metrics, 0x3000));
  CHECK(uc_mem_read(uc, k_dpmi_ldt_address + 0x3000, got, 8) == UC_ERR_OK);
  if (kind != 1) CHECK(memcmp(got, (uint8_t[8]){0}, 8) == 0);
out:
  if (uc != NULL) uc_close(uc);
  return pass;
}

static int probes_contract(void) {
  int pass = 1;
  uc_engine *uc = NULL;
  DazeUnicornContext context = {0};
  CHECK(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  CHECK(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  const uint16_t functions[] = {0x4300, 0xfb43, 0xfb42, 0x1687, 0x1600};
  for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]); ++i) {
    set_reg16(uc, UC_X86_REG_AX, functions[i]);
    set_reg16(uc, UC_X86_REG_BX, i == 1 ? 0x100 : 0x14);
    set_reg16(uc, UC_X86_REG_CX, 1);
    set_reg16(uc, UC_X86_REG_IP, 0x100);
    CHECK(daze_dispatch_interrupt(uc, DAZE_INT_MULTIPLEX, &context.engine, &context.run,
                                  &context.process, NULL));
    CHECK(get_reg16(uc, UC_X86_REG_IP) == 0x102);
    CHECK(get_reg16(uc, UC_X86_REG_AX) == (i == 3 ? 0 : i == 4 ? 1 : functions[i]));
    if (i == 2) CHECK(get_reg16(uc, UC_X86_REG_BX) == 1);
    if (i == 3)
      CHECK(get_reg16(uc, UC_X86_REG_ES) == k_dpmi_entry_segment &&
            get_reg16(uc, UC_X86_REG_DI) == 0);
  }
  CHECK(daze_dispatch_interrupt(uc, 8, &context.engine, &context.run, &context.process, NULL));
  CHECK(!daze_dispatch_interrupt(uc, 0x66, &context.engine, &context.run, &context.process, NULL));
  context.process.dos_process.dos_vector_segment[0x3f] = 0x3000;
  context.process.dos_process.dos_vector_offset[0x3f] = 0x400;
  set_reg16(uc, UC_X86_REG_CS, 0x1000);
  set_reg16(uc, UC_X86_REG_IP, 0x123);
  set_reg16(uc, UC_X86_REG_SS, 0x2000);
  set_reg16(uc, UC_X86_REG_SP, 0x800);
  set_reg32(uc, UC_X86_REG_EFLAGS, 0x303);
  CHECK(daze_dispatch_interrupt(uc, 0x3f, &context.engine, &context.run, &context.process, NULL));
  uint8_t frame[6];
  CHECK(uc_mem_read(uc, 0x207fa, frame, 6) == UC_ERR_OK);
  CHECK(daze_read_u16(frame) == 0x123 && daze_read_u16(frame + 2) == 0x1000 &&
        daze_read_u16(frame + 4) == 0x303);
  CHECK(get_reg16(uc, UC_X86_REG_SP) == 0x7fa && get_reg32(uc, UC_X86_REG_EFLAGS) == 3);
  CHECK(context.run.resume_address == 0x30400 && get_reg16(uc, UC_X86_REG_CS) == 0x3000);
  set_reg16(uc, UC_X86_REG_SP, 5);
  CHECK(!daze_dispatch_interrupt(uc, 0x3f, &context.engine, &context.run, &context.process, NULL));
out:
  if (uc != NULL) uc_close(uc);
  return pass;
}

static int transition_case(int kind) {
  int pass = 1;
  uc_engine *uc = NULL;
  DazeUnicornContext context = {0};
  CHECK(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  CHECK(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  daze_dos_process_state_init(&context.process.dos_process, 0x1000);
  context.process.resident_image_end = kind == 9 ? k_dpmi_linear_arena_limit : 0x20000;
  set_reg16(uc, UC_X86_REG_AX, kind == 1 ? 2 : kind == 10 ? 1 : 0);
  set_reg16(uc, UC_X86_REG_DS, kind == 5 ? 0 : 0x1000);
  set_reg16(uc, UC_X86_REG_SS, 0x2000);
  set_reg16(uc, UC_X86_REG_SP, kind == 3 ? 0xffe : 0x800);
  uint8_t words[4];
  daze_write_u16(words, 0x123);
  daze_write_u16(words + 2, 0x1000);
  CHECK(uc_mem_write(uc, kind == 3 ? 0x20ffe : 0x20800, words, 4) == UC_ERR_OK);
  uint8_t environment[2];
  daze_write_u16(environment, 0x700);
  CHECK(uc_mem_write(uc, 0x1002c, environment, 2) == UC_ERR_OK);
  if (kind == 2) CHECK(uc_mem_unmap(uc, 0x20000, 0x1000) == UC_ERR_OK);
  if (kind == 3) CHECK(uc_mem_unmap(uc, 0x21000, 0x1000) == UC_ERR_OK);
  if (kind == 4) CHECK(uc_mem_unmap(uc, 0x10000, 0x1000) == UC_ERR_OK);
  if (kind == 6) CHECK(uc_mem_unmap(uc, k_dpmi_gdt_address, 0x1000) == UC_ERR_OK);
  if (kind == 7) CHECK(uc_mem_unmap(uc, k_dpmi_ldt_address, 0x1000) == UC_ERR_OK);
  if (kind == 8) CHECK(uc_mem_unmap(uc, 0x2000, 0x1000) == UC_ERR_OK);
  int prepared = daze_setup_prepare_dpmi_transition(uc, &context.engine, &context.process);
  CHECK(prepared == (kind == 0 || kind == 10));
  if (prepared) {
    CHECK(context.process.dpmi.real_mode_state_valid);
    CHECK(context.process.dpmi.real_mode_state.ds == 0x1000 &&
          context.process.dpmi.real_mode_state.ss == 0x2000);
    uint8_t entry[2];
    CHECK(uc_mem_read(uc, 0x2000, entry, 2) == UC_ERR_OK);
    CHECK(entry[0] != 0);
    CHECK(!(get_reg32(uc, UC_X86_REG_EFLAGS) & 1));
  }
out:
  daze_dos_process_state_dispose(&context.process.dos_process);
  if (uc != NULL) uc_close(uc);
  return pass;
}

static int exec_trace_contract(void) {
  FILE *trace = tmpfile();
  int saved_stderr = dup(STDERR_FILENO);
  if (trace == NULL || saved_stderr < 0) return 0;
  if (setenv("DAZE_EXEC_TRACE", "1", 1) != 0 || dup2(fileno(trace), STDERR_FILENO) < 0) return 0;
  int pass = exec_case(0);
  fflush(stderr);
  pass &= dup2(saved_stderr, STDERR_FILENO) >= 0;
  close(saved_stderr);
  unsetenv("DAZE_EXEC_TRACE");
  rewind(trace);
  char bytes[8192];
  size_t size = fread(bytes, 1, sizeof(bytes) - 1, trace);
  bytes[size] = 0;
  fclose(trace);
  pass &=
    size < sizeof(bytes) - 1 &&
    strstr(bytes, "exec: request ds:dx=1000:0200 es:bx=1000:0300 path=CHILD.EXE parameter") != NULL;
  pass &= strstr(bytes, " tail 02 20 78 fcb1 00 46 49 4c 45") != NULL;
  pass &= strstr(bytes, " fcb2 00 46 49 4c 45") != NULL;
  pass &= strstr(bytes, "return to EXEC parent at 1000:0100") != NULL;
  if (!pass) fprintf(stderr, "EXEC trace contract failed: %s\n", bytes);
  return pass;
}

int main(void) {
  int pass = 1;
  for (int kind = 0; kind <= 18; ++kind)
    pass &= exec_case(kind);
  for (int interrupt = 0; interrupt < 2; ++interrupt)
    for (int kind = 0; kind <= 23; ++kind)
      pass &= procedure_case(interrupt, kind);
  for (int kind = 0; kind < 8; ++kind)
    pass &= raw_vectors_case(kind);
  pass &= probes_contract();
  for (int kind = 0; kind <= 10; ++kind)
    pass &= transition_case(kind);
  pass &= exec_trace_contract();
  return pass ? 0 : 1;
}
