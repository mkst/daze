#include "rm_procedure.h"
#include "descriptor.h"
#include "byte_order.h"
#include "runner_private.h"
#include "machine_access.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static int run_case(int kind) {
  DazeKvmMachine m;
  const int init = daze_kvm_machine_init(&m, 0x40000);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  if (kind == 26) m.sync_regs_mask = 0;
  uint8_t *guest = m.guest;
  DazeRunMetrics metrics = {.enabled = 1};
  if (kind & 1) m.run_metrics = &metrics;
  if (kind == 24) {
    metrics.enabled = 0;
    m.run_metrics = &metrics;
  }
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  DazeDosProcessState dos;
  daze_dos_process_state_init(&dos, 0x1000);
  DazeDosMemory memory;
  daze_dos_memory_init(&memory, 0x3000, 0xa000);
  DazeDpmiLinearMemory linear;
  daze_dpmi_linear_memory_init(&linear, 0x20000, 0x30000);
  uint8_t used[32] = {0};
  DazeKvmDpmiMediator mediator = {.guest = guest,
                                  .guest_size = m.guest_size,
                                  .dos_memory = &memory,
                                  .linear_memory = &linear,
                                  .gdt_address = 0x6000,
                                  .gdt_size = 0x48,
                                  .ldt_address = 0x6800,
                                  .ldt_size = 0x100,
                                  .ldt_used = used,
                                  .ldt_used_count = sizeof(used),
                                  .ldt_first_index = 16,
                                  .rm_procedure_present = 1,
                                  .rm_procedure_is_interrupt = kind == 1};
  mediator.rm_procedure = (DazeDpmiRmProcedure){.target_cs = 0x400,
                                                .target_ip = 0,
                                                .frame_ss = 0x1800,
                                                .frame_sp = 0x300,
                                                .procedure_sp = kind == 1 ? 0x2fa : 0x2fc,
                                                .frame_address = 0x8000,
                                                .stack_address = kind == 1 ? 0x182fa : 0x182fc};
  uint8_t *frame = guest + 0x8000;
  memset(frame, 0x5a, DAZE_DPMI_RM_FRAME_SIZE);
  daze_write_u32(frame + DAZE_DPMI_RM_EAX, 0xa5a51234);
  daze_write_u32(frame + DAZE_DPMI_RM_EBX, 0x11223344);
  daze_write_u16(frame + DAZE_DPMI_RM_FLAGS, 2);
  daze_write_u16(frame + DAZE_DPMI_RM_DS, 0x1000);
  daze_write_u16(frame + DAZE_DPMI_RM_ES, 0x1200);
  daze_write_u16(frame + DAZE_DPMI_RM_FS, 0);
  daze_write_u16(frame + DAZE_DPMI_RM_GS, 0);
  const uint8_t target[] = {0xbb, 0x78, 0x56, 0xb9, 0xbc, 0x9a, 0xcb};
  memcpy(guest + 0x4000, target, sizeof(target));
  if (kind == 1) guest[0x4006] = 0xcf;
  if (kind == 2) guest[0x4000] = 0xf4;
  if (kind == 3) {
    const uint8_t io[] = {0xb0, 0xee, 0xe6, 0x77, 0xcb};
    memcpy(guest + 0x4000, io, sizeof(io));
  }
  if (kind == 4) {
    const uint8_t io[] = {0xe4, 0x77, 0xcb};
    memcpy(guest + 0x4000, io, sizeof(io));
  }
  if (kind == 5) {
    const uint8_t io[] = {0xb0, 0xee, 0xe6, 0xf4, 0xcb};
    memcpy(guest + 0x4000, io, sizeof(io));
  }
  if (kind == 6) {
    const uint8_t io[] = {0xe4, 0x21, 0xe4, 0xa1, 0xe6, 0, 0xcb};
    memcpy(guest + 0x4000, io, sizeof(io));
  }
  if (kind == 7) {
    mediator.rm_procedure.parameter_bytes = 4;
    mediator.rm_procedure.procedure_sp -= 4;
    mediator.rm_procedure.stack_address -= 4;
    const uint8_t code[] = {0x89, 0xe5, 0x8b, 0x5e, 4, 0x8b, 0x4e, 6, 0xcb};
    memcpy(guest + 0x4000, code, sizeof(code));
  }
  if (kind == 18) {
    const uint8_t wide_out[] = {0xe7, 0x77, 0xcb}; /* out 77h,ax; retf */
    memcpy(guest + 0x4000, wide_out, sizeof(wide_out));
  }
  if (kind == 19) {
    const uint8_t loop[] = {0xe6, 0, 0xeb, 0xfc}; /* out 0,al; jmp short -4 */
    memcpy(guest + 0x4000, loop, sizeof(loop));
  }
  if (kind == 25 || kind == 26) {
    const uint8_t image[] = {
      0x66, 0xb8, 0x44, 0x33, 0x22, 0x11, /* mov eax,11223344h */
      0x66, 0xbb, 0x55, 0x44, 0x33, 0x22, /* mov ebx,22334455h */
      0x66, 0xb9, 0x66, 0x55, 0x44, 0x33, /* mov ecx,33445566h */
      0x66, 0xba, 0x77, 0x66, 0x55, 0x44, /* mov edx,44556677h */
      0x66, 0xbe, 0x88, 0x77, 0x66, 0x55, /* mov esi,55667788h */
      0x66, 0xbf, 0x99, 0x88, 0x77, 0x66, /* mov edi,66778899h */
      0x66, 0xbd, 0xaa, 0x99, 0x88, 0x77, /* mov ebp,778899aah */
      0x66, 0x50,                         /* push eax */
      0xb8, 0x00, 0x11, 0x8e, 0xc0,       /* mov ax,1100h; mov es,ax */
      0xb8, 0x00, 0x12, 0x8e, 0xd8,       /* mov ax,1200h; mov ds,ax */
      0xb8, 0x00, 0x13, 0x8e, 0xe0,       /* mov ax,1300h; mov fs,ax */
      0xb8, 0x00, 0x14, 0x8e, 0xe8,       /* mov ax,1400h; mov gs,ax */
      0x66, 0x58,                         /* pop eax */
      0x68, 0xd7, 0x0e, 0x9d,             /* push 0ed7h; popf */
      0xcb,                               /* retf */
    };
    memcpy(guest + 0x4000, image, sizeof(image));
  }
  if (kind >= 11 && kind < 18) {
    const uint8_t dos_gate[] = {0x50, 0xb0, 0x21, 0xe6, 0xf4, 0x83, 0xc4, 2, 0xcf};
    const uint8_t dpmi_gate[] = {0x50, 0xb0, 0x31, 0xe6, 0xf4, 0x83, 0xc4, 2, 0xcf};
    memcpy(guest + 0x9000, dos_gate, sizeof(dos_gate));
    memcpy(guest + 0x9040, dpmi_gate, sizeof(dpmi_gate));
    daze_write_u16(guest + 0x21 * 4 + 2, 0x900);
    daze_write_u16(guest + 0x31 * 4, 0x40);
    daze_write_u16(guest + 0x31 * 4 + 2, 0x900);
    uint8_t code[] = {0xb8, 0, 0x30, 0xcd, 0x21, 0xcb};
    if (kind == 12) code[2] = 0xff;
    if (kind >= 13) {
      const uint8_t dpmi[] = {0xbb, 0, 0, 0xb9, 0, 0x10, 0xb8, 1, 5, 0xcd, 0x31, 0xcb};
      memcpy(guest + 0x4000, dpmi, sizeof(dpmi));
      if (kind == 14) guest[0x4005] = 0;
      if (kind == 15) {
        guest[0x4004] = 2;
        guest[0x4005] = 0;
        guest[0x4007] = 0;
        guest[0x4008] = 0;
      }
      if (kind == 16) {
        guest[0x4001] = 0xff;
        guest[0x4002] = 0xff;
        guest[0x4007] = 8;
        guest[0x4008] = 0;
      }
      if (kind == 17) {
        guest[0x4007] = 0xff;
        guest[0x4008] = 0xff;
      }
    } else
      memcpy(guest + 0x4000, code, sizeof(code));
  }
  const uint8_t parked_code[] = {0xb0, 0x31, 0xe6, 0xf4, 0xf4, 0x90, 0x90, 0x90};
  memcpy(guest + 0x2500, parked_code, sizeof(parked_code));
  int fail =
    daze_kvm_machine_set_real_mode(&m, 0x250, 0, 0x1800, 0x100, 0, 0) != DAZE_KVM_MACHINE_OK;
  struct kvm_sregs sr;
  struct kvm_regs r = {.rip = 0x500,
                       .rsp = 0x100,
                       .rbp = 0x100,
                       .rflags = 2,
                       .rbx = 0xaaaa,
                       .rcx = 0xbbbb,
                       .rdx = 0xcccc};
  if (ioctl(m.vcpu, KVM_GET_SREGS, &sr) < 0) fail = 1;
  sr.cr0 = 0x11;
  sr.cs = (struct kvm_segment){
    .selector = 0x28, .base = 0x2000, .limit = 0xffff, .type = 0xb, .present = 1, .s = 1};
  sr.gdt.base = 0x6000;
  sr.gdt.limit = 0x47;
  daze_dpmi_descriptor_encode(guest + 0x6028, 0x2000, 0xffff, 0x9a, 0);
  daze_write_u16(guest + 0x1810c, 0x1357);
  daze_write_u16(guest + 0x1810e, 0x2468);
  if (ioctl(m.vcpu, KVM_SET_SREGS, &sr) < 0 || ioctl(m.vcpu, KVM_SET_REGS, &r) < 0) fail = 1;
  DazeKvmDpmiEntryResult boundary;
  if (daze_kvm_dpmi_entry_continue_once(&m, &boundary) != DAZE_KVM_DPMI_ENTRY_OK ||
      boundary.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_PIO)
    fail = 1;
  struct kvm_regs parked;
  ioctl(m.vcpu, KVM_GET_REGS, &parked);
  uint8_t before[DAZE_DPMI_RM_FRAME_SIZE];
  memcpy(before, frame, sizeof(before));
  if (kind == 8) mediator.rm_procedure.frame_address = m.guest_size - 1;
  if (kind == 9) mediator.rm_procedure.stack_address = UINT32_MAX;
  if (kind == 10) mediator.rm_procedure_present = 0;
  if (kind == 20) {
    mediator.rm_procedure.parameter_bytes = 4;
    sr.ss.limit = 0x100;
    if (daze_kvm_machine_set_sregs(&m, &sr) != DAZE_KVM_MACHINE_OK) fail = 1;
  }
  if (kind == 21) {
    mediator.rm_procedure.parameter_bytes = 4;
    sr.ss.base = UINT32_MAX;
    sr.ss.limit = UINT32_MAX;
    if (daze_kvm_machine_set_sregs(&m, &sr) != DAZE_KVM_MACHINE_OK) fail = 1;
  }
  if (kind == 22) {
    mediator.rm_procedure.parameter_bytes = 4;
    sr.ss.base = m.guest_size;
    sr.ss.limit = UINT32_MAX;
    if (daze_kvm_machine_set_sregs(&m, &sr) != DAZE_KVM_MACHINE_OK) fail = 1;
  }
  FILE *dump = NULL;
  int saved_stderr = -1;
  if (kind == 2) {
    dump = tmpfile();
    saved_stderr = dup(STDERR_FILENO);
    if (dump == NULL || saved_stderr < 0 || dup2(fileno(dump), STDERR_FILENO) < 0 ||
        setenv("DAZE_KVM_RM_CRASH_DUMP", "1", 1) != 0)
      fail = 1;
  }
  DazeKvmDpmiEntryResult successor;
  const int status = daze_kvm_rm_procedure_reflect(
    &(DazeKvmRmProcedureInput){.machine = &m,
                               .mediator = &mediator,
                               .files = &files,
                               .process_state = &dos,
                               .dpmi_entry_segment = 0x200,
                               .protected_return_linear = kind == 23 ? 0x2504 : 0},
    &successor);
  const int success = kind == 0 || kind == 1 || kind == 6 || kind == 7 || kind == 11 ||
                      (kind >= 13 && kind <= 16) || kind == 23 || kind == 24 || kind == 25 ||
                      kind == 26;
  if (kind == 2) {
    if (unsetenv("DAZE_KVM_RM_CRASH_DUMP") != 0 || fflush(stderr) != 0 ||
        dup2(saved_stderr, STDERR_FILENO) < 0)
      fail = 1;
    if (saved_stderr >= 0) close(saved_stderr);
    if (dump != NULL) {
      rewind(dump);
      char text[4096];
      size_t size = fread(text, 1, sizeof(text) - 1, dump);
      text[size] = 0;
      fail |= strstr(text, "gprs rax=") == NULL || strstr(text, "gdtr base=") == NULL ||
              strstr(text, "cs:ip") == NULL || strstr(text, "context@") == NULL;
      fclose(dump);
    }
  }
  struct kvm_regs after;
  struct kvm_sregs safter;
  daze_kvm_machine_get_regs(&m, &after);
  daze_kvm_machine_get_sregs(&m, &safter);
  fail |= status != success;
  if (success) {
    fail |= successor.observation.kind !=
              (kind == 23 ? DAZE_KVM_DPMI_ENTRY_EXIT_DEBUG : DAZE_KVM_DPMI_ENTRY_EXIT_HLT) ||
            successor.cs != 0x28 || successor.cs_base != 0x2000 ||
            successor.rip != (kind == 23 ? 0x504 : 0x505) || !(successor.cr0 & 1) ||
            after.rbx != parked.rbx || after.rcx != parked.rcx || after.rsp != parked.rsp ||
            safter.gdt.base != sr.gdt.base ||
            memcmp(frame + DAZE_DPMI_RM_IP, before + DAZE_DPMI_RM_IP, 8) != 0;
    if (kind == 0 || kind == 1 || kind == 7)
      fail |= (uint16_t)daze_read_u32(frame + DAZE_DPMI_RM_EBX) != (kind == 7 ? 0x1357 : 0x5678) ||
              (uint16_t)daze_read_u32(frame + DAZE_DPMI_RM_ECX) != (kind == 7 ? 0x2468 : 0x9abc);
    if (kind == 1) fail |= daze_read_u32(frame + DAZE_DPMI_RM_EAX) != 0xa5a51234;
    if (kind == 6) fail |= (uint8_t)daze_read_u32(frame + DAZE_DPMI_RM_EAX) != 0;
    if (kind == 11) fail |= (uint16_t)daze_read_u32(frame + DAZE_DPMI_RM_EAX) != 5;
    if (kind == 13)
      fail |= !linear.allocations[0].in_use || linear.allocations[0].allocated_size != 0x1000;
    if (kind == 14)
      fail |= (uint16_t)daze_read_u32(frame + DAZE_DPMI_RM_EAX) != 0x8012 ||
              !(daze_read_u16(frame + DAZE_DPMI_RM_FLAGS) & 1) || linear.allocations[0].in_use;
    if (kind == 15)
      fail |= !used[16] || !used[17] || (uint16_t)daze_read_u32(frame + DAZE_DPMI_RM_EAX) != 0x84;
    if (kind == 16)
      fail |= (uint16_t)daze_read_u32(frame + DAZE_DPMI_RM_EAX) != 0x8021 ||
              !(daze_read_u16(frame + DAZE_DPMI_RM_FLAGS) & 1);
    if (kind == 25 || kind == 26) {
      const unsigned offsets[] = {DAZE_DPMI_RM_EAX, DAZE_DPMI_RM_EBX, DAZE_DPMI_RM_ECX,
                                  DAZE_DPMI_RM_EDX, DAZE_DPMI_RM_ESI, DAZE_DPMI_RM_EDI,
                                  DAZE_DPMI_RM_EBP};
      for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i)
        fail |= daze_read_u32(frame + offsets[i]) != 0x11223344u + i * 0x11111111u;
      fail |= daze_read_u16(frame + DAZE_DPMI_RM_FLAGS) != 0x0ed7 ||
              daze_read_u16(frame + DAZE_DPMI_RM_ES) != 0x1100 ||
              daze_read_u16(frame + DAZE_DPMI_RM_DS) != 0x1200 ||
              daze_read_u16(frame + DAZE_DPMI_RM_FS) != 0x1300 ||
              daze_read_u16(frame + DAZE_DPMI_RM_GS) != 0x1400;
    }
    if (kind & 1)
      fail |= metrics.kvm_rm_procedure_calls != 1 || metrics.kvm_rm_procedure_run_calls == 0;
  } else {
    fail |= memcmp(before, frame, sizeof(before)) != 0 || after.rbx != parked.rbx ||
            after.rsp != parked.rsp || safter.cs.base != sr.cs.base || !(safter.cr0 & 1);
  }
  if (fail)
    fprintf(stderr, "RM case %d status=%d expected=%d successor=%d cs:ip=%04x:%x\n", kind, status,
            success, successor.observation.kind, successor.cs, successor.rip);
  if (fail && (kind == 25 || kind == 26))
    fprintf(stderr,
            "RM return exit=%u eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x "
            "ebp=%08x flags=%04x es=%04x ds=%04x fs=%04x gs=%04x\n",
            ((const struct kvm_run *)m.run)->exit_reason, daze_read_u32(frame + DAZE_DPMI_RM_EAX),
            daze_read_u32(frame + DAZE_DPMI_RM_EBX), daze_read_u32(frame + DAZE_DPMI_RM_ECX),
            daze_read_u32(frame + DAZE_DPMI_RM_EDX), daze_read_u32(frame + DAZE_DPMI_RM_ESI),
            daze_read_u32(frame + DAZE_DPMI_RM_EDI), daze_read_u32(frame + DAZE_DPMI_RM_EBP),
            daze_read_u16(frame + DAZE_DPMI_RM_FLAGS), daze_read_u16(frame + DAZE_DPMI_RM_ES),
            daze_read_u16(frame + DAZE_DPMI_RM_DS), daze_read_u16(frame + DAZE_DPMI_RM_FS),
            daze_read_u16(frame + DAZE_DPMI_RM_GS));
  if (kind == 24)
    fail |= metrics.kvm_rm_procedure_calls != 0 || metrics.kvm_rm_procedure_run_calls != 0;
  daze_dos_process_state_dispose(&dos);
  daze_kvm_machine_destroy(&m);
  return fail;
}
int main(void) {
  for (int kind = 0; kind < 27; ++kind) {
    int status = run_case(kind);
    if (status) return status;
  }
  return 0;
}
#else
int main(void) {
  return 77;
}
#endif
