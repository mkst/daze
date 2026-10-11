#include "child_context.h"

#include "byte_order.h"
#include "raw_switch.h"
#include "guest_memory_layout.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>
#endif

static int snapshot_lifecycle(int protected_mode) {
  DazeKvmMachine machine;
  if (daze_kvm_machine_init(&machine, 0x50000) != DAZE_KVM_MACHINE_OK) return 1;
  DazeKvmChildContext context = {0};
  DazeKvmRunnerRequestCommon layout = {.psp_segment = 0x100, .load_segment = 0x500};
  DazeDosProcessState dos;
  DazeDosMemory memory;
  DazeDpmiProcessState dpmi = {.next_ldt_index = 0x22, .virtual_interrupts_enabled = 1};
  daze_dos_process_state_init(&dos, 0x100);
  daze_dos_memory_init(&memory, 0x3000, 0xa000);
  dos.find.directory = opendir("/tmp");
  int failed = dos.find.directory == NULL;
  int child_search = -1;
  if (failed) goto out;
  const int parent_search = dirfd(dos.find.directory);
  const DazeDosProcessState parent_dos = dos;
  const DazeDosMemory parent_memory = memory;
  const DazeDpmiProcessState parent_dpmi = dpmi;
  memset(machine.guest, 0x5a, machine.guest_size);
  if (daze_kvm_machine_set_real_mode(&machine, 0x1234, 0x56, 0x2345, 0x7890, 0x3456, 0x4567) !=
        DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_set_general_registers(&machine, 0x1122, 0x3344, 0x5566, 0x7788, 0x99aa,
                                             0xbbcc) != DAZE_KVM_MACHINE_OK) {
    failed = 1;
    goto out;
  }
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) != 0) {
    failed = 1;
    goto out;
  }
  if (protected_mode) {
    /* Cached bases and table addresses deliberately differ from selector arithmetic. */
    sregs.cr0 = 1;
    sregs.cs.selector = 8;
    sregs.cs.base = 0x15000;
    sregs.cs.type = 0xb;
    sregs.ds.selector = 0x14;
    sregs.ds.base = 0x26000;
    sregs.gdt.base = 0x42000;
    sregs.gdt.limit = 0xff;
    sregs.ldt.base = 0x43000;
    sregs.ldt.limit = 0xff;
    sregs.ldt.selector = 0x18;
    sregs.ldt.type = 2;
    sregs.ldt.present = 1;
    sregs.ldt.unusable = 0;
    if (ioctl(machine.vcpu, KVM_SET_SREGS, &sregs) != 0) {
      failed = 1;
      goto out;
    }
  }
  if (ioctl(machine.vcpu, KVM_GET_REGS, &regs) != 0 ||
      ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) != 0) {
    failed = 1;
    goto out;
  }
#else
  (void)protected_mode;
#endif
  DazeKvmMachine invalid = machine;
  invalid.vcpu = -1;
  if (daze_kvm_child_context_capture(&context, &invalid, &layout, &dos, &memory, &dpmi) ||
      context.active || context.parent_dpmi != NULL || context.machine.guest_bytes != NULL ||
      memcmp(&dos, &parent_dos, sizeof(dos)) != 0 ||
      memcmp(&memory, &parent_memory, sizeof(memory)) != 0 ||
      memcmp(&dpmi, &parent_dpmi, sizeof(dpmi)) != 0) {
    failed = 1;
    goto out;
  }
  invalid.vcpu = parent_search;
  if (daze_kvm_child_context_capture(&context, &invalid, &layout, &dos, &memory, &dpmi) ||
      context.active || context.parent_dpmi != NULL ||
      memcmp(&dos, &parent_dos, sizeof(dos)) != 0 ||
      memcmp(&memory, &parent_memory, sizeof(memory)) != 0 ||
      memcmp(&dpmi, &parent_dpmi, sizeof(dpmi)) != 0) {
    failed = 1;
    goto out;
  }
  if (!daze_kvm_child_context_capture(&context, &machine, &layout, &dos, &memory, &dpmi) ||
      dos.find.directory != NULL || dos.psp_segment != 0 || memory.next_segment != 0 ||
      dpmi.next_ldt_index != 0 || context.parent_dos.find.directory != parent_dos.find.directory) {
    failed = 1;
    goto out;
  }
  const DazeKvmChildContext before = context;
  if (daze_kvm_child_context_capture(&context, &machine, &layout, &dos, &memory, &dpmi) ||
      memcmp(&context, &before, sizeof(context)) != 0) {
    failed = 1;
    goto out;
  }
  daze_dos_process_state_init(&dos, 0x3000);
  dos.find.directory = opendir("/tmp");
  if (dos.find.directory == NULL) {
    failed = 1;
    goto out;
  }
  child_search = dirfd(dos.find.directory);
  const DazeDosProcessState child_dos = dos;
  memset(machine.guest, 0xa5, machine.guest_size);
  invalid = machine;
  invalid.guest_size--;
  if (daze_kvm_child_context_restore(&context, &invalid, &dos, &memory, &dpmi) ||
      memcmp(&context, &before, sizeof(context)) != 0 ||
      memcmp(&dos, &child_dos, sizeof(dos)) != 0 || fcntl(parent_search, F_GETFD) < 0 ||
      fcntl(child_search, F_GETFD) < 0 || ((uint8_t *)machine.guest)[0] != 0xa5) {
    failed = 1;
    goto out;
  }
  context.child_image.bytes = malloc(32);
  context.child_image.size = 32;
  if (context.child_image.bytes == NULL ||
      daze_kvm_machine_set_real_mode(&machine, 0, 0, 0, 0x100, 0, 0) != DAZE_KVM_MACHINE_OK ||
      !daze_kvm_child_context_restore(&context, &machine, &dos, &memory, &dpmi) || context.active ||
      context.parent_dpmi != NULL || context.child_image.bytes != NULL ||
      context.machine.guest_bytes != NULL || context.machine.cpu_state != NULL ||
      memcmp(&dos, &parent_dos, sizeof(dos)) != 0 ||
      memcmp(&memory, &parent_memory, sizeof(memory)) != 0 ||
      memcmp(&dpmi, &parent_dpmi, sizeof(dpmi)) != 0 || fcntl(child_search, F_GETFD) != -1 ||
      errno != EBADF || fcntl(parent_search, F_GETFD) < 0 ||
      daze_kvm_child_context_restore(&context, &machine, &dos, &memory, &dpmi)) {
    failed = 1;
    goto out;
  }
  for (size_t i = 0; i < machine.guest_size; ++i)
    if (((uint8_t *)machine.guest)[i] != 0x5a) {
      failed = 1;
      break;
    }
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  struct kvm_regs restored_regs;
  struct kvm_sregs restored_sregs;
  if (ioctl(machine.vcpu, KVM_GET_REGS, &restored_regs) != 0 ||
      ioctl(machine.vcpu, KVM_GET_SREGS, &restored_sregs) != 0 ||
      memcmp(&regs, &restored_regs, sizeof(regs)) != 0 ||
      memcmp(&sregs, &restored_sregs, sizeof(sregs)) != 0)
    failed = 1;
#endif
out:
  daze_kvm_child_context_dispose(&context);
  daze_kvm_child_context_dispose(&context);
  daze_dos_process_state_dispose(&dos);
  daze_kvm_machine_destroy(&machine);
  if (failed) fprintf(stderr, "child snapshot lifecycle failed mode=%d\n", protected_mode);
  return failed;
}

static int resident_rejections(DazeKvmChildContext *context, DazeKvmMachine *machine,
                               const DazeDosProcessState *child_dos,
                               const DazeDosMemory *child_memory,
                               const DazeDpmiProcessState *child_dpmi) {
  const DazeKvmChildContext saved = *context;
  for (int kind = 0; kind < 6; ++kind) {
    DazeDosProcessState dos = *child_dos;
    DazeDosMemory memory = *child_memory;
    DazeDpmiProcessState dpmi = *child_dpmi;
    uint16_t paragraphs = 4;
    if (kind == 0) paragraphs = 0;
    if (kind == 1) dos.psp_segment = 0xffff;
    if (kind == 2) memset(memory.allocations, 0, sizeof(memory.allocations));
    if (kind == 3) paragraphs = 9;
    if (kind == 4) context->parent_memory.next_segment = 0x4000;
    if (kind == 5) ((uint8_t *)machine->guest)[0x2000] = 0;
    const DazeKvmChildContext before = *context;
    const DazeDosProcessState before_dos = dos;
    const DazeDosMemory before_memory = memory;
    const DazeDpmiProcessState before_dpmi = dpmi;
    const int rejected = !daze_kvm_child_context_restore_resident(context, machine, &dos, &memory,
                                                                  &dpmi, paragraphs, NULL) &&
                         memcmp(context, &before, sizeof(before)) == 0 &&
                         memcmp(&dos, &before_dos, sizeof(dos)) == 0 &&
                         memcmp(&memory, &before_memory, sizeof(memory)) == 0 &&
                         memcmp(&dpmi, &before_dpmi, sizeof(dpmi)) == 0;
    *context = saved;
    if (kind == 5) ((uint8_t *)machine->guest)[0x2000] = 0xfa;
    if (!rejected) {
      fprintf(stderr, "resident rejection %d altered ownership or process state\n", kind);
      return 1;
    }
  }
  return 0;
}

static int run_case(int short_ldt) {
  DazeKvmMachine machine;
  const int init = daze_kvm_machine_init(&machine, 0x50000);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  uint8_t *guest = machine.guest;
  DazeDosMemory projection_memory;
  daze_dos_memory_init(&projection_memory, 0x3000, 0x3100);
  const DazeDosAllocation *projected_block = daze_dos_memory_allocate(&projection_memory, 8);
  DazeKvmResidentGdtState projections = {.ldt_base = 0x4000, .ldt_limit = 0xffff};
  uint8_t expected_projection[8];
  if (projected_block == NULL ||
      !daze_raw_vector_projection_descriptor(projected_block, 0x3004, expected_projection) ||
      !daze_raw_vector_projection_record(projections.raw_vector_projections,
                                         DAZE_RAW_VECTOR_PROJECTION_MAX, 0x3004, 0x3000, 8, 1))
    return 1;
  memcpy(guest + 0x7000, expected_projection, 8);
  if (!daze_kvm_resident_vector_projections_refresh(&machine, &projections, &projection_memory) ||
      memcmp(guest + 0x7000, expected_projection, 8) != 0 ||
      !daze_dos_memory_release(&projection_memory, 0x3000) ||
      !daze_kvm_resident_vector_projections_refresh(&machine, &projections, &projection_memory) ||
      memcmp(guest + 0x7000, (uint8_t[8]){0}, 8) != 0 ||
      projections.raw_vector_projections[0].in_use)
    return 1;
  const uint8_t program[] = {
    0xb0, 0x11, /* mov al,0x11 */
    0xe6, 0xf4  /* out 0xf4,al */
  };
  DazeKvmRunnerRequestCommon layout = {.psp_segment = 0x0ff0, .load_segment = 0x1000};
  DazeDosProcessState dos;
  DazeDosMemory memory;
  DazeDpmiProcessState dpmi = {.next_ldt_index = 0x2a, .virtual_interrupts_enabled = 1};
  DazeKvmChildContext context = {0};
  int result = 1;
  memcpy(guest, program, sizeof(program));
  daze_dos_process_state_init(&dos, 0x0ff0);
  daze_dos_process_state_set_dta(&dos, 0x1234, 0x5678);
  daze_dos_memory_init(&memory, 0x3000, 0xa000);
  if (daze_dos_memory_allocate(&memory, short_ldt ? 8 : 4) == NULL ||
      daze_kvm_machine_set_real_mode(&machine, 0, 0, 0, 0xfffe, 0, 0) != DAZE_KVM_MACHINE_OK ||
      !daze_kvm_child_context_capture(&context, &machine, &layout, &dos, &memory, &dpmi)) {
    goto out;
  }
  daze_dos_process_state_init(&dos, 0x3000);
  daze_dos_process_state_set_dta(&dos, 0x3000, 0x0080);
  daze_dos_memory_init(&memory, 0x4000, 0xa000);
  dpmi.next_ldt_index = 0;
  guest[0] = 0xf4;
  if (!daze_kvm_child_context_restore(&context, &machine, &dos, &memory, &dpmi)) goto out;
  DazeKvmPortAccess access = {0};
  if (dos.dta_segment != 0x1234 || dos.dta_offset != 0x5678 ||
      memory.next_segment != (short_ldt ? 0x3008 : 0x3004) || dpmi.next_ldt_index != 0x2a ||
      daze_kvm_machine_run_port_access(&machine, &access) != DAZE_KVM_MACHINE_OK ||
      access.direction != DAZE_KVM_PORT_OUT || access.port != 0xf4 || access.value != 0x11 ||
      guest[0] != program[0])
    goto out;

  DazeKvmChildContext resident = {0};
  DazeKvmResidentGdtState retained = {0};
  const DazeDosMemory child_memory = memory;
  guest[0x30000] = 0x11;
  guest[0x30040] = 0x22;
  const uint32_t raw_ivt = DAZE_KVM_RAW_SWITCH_GATE_VECTOR * 4u;
  const uint8_t raw_handler[DAZE_KVM_RAW_SWITCH_GATE_HANDLER_SIZE] = {
    0x50,       /* push ax */
    0xb0, 0x18, /* mov al,0x18 */
    0xe6, 0xf4, /* out 0xf4,al */
    0xf4        /* hlt */
  };
  static const uint8_t resident_transition[] = {
    0xfa,                               /* cli */
    0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
    0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
    0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
    0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
    0xea, 0x20, 0x00, 0x20, 0x00,       /* jmp far 0x20:0x20 */
  };
  static const uint8_t resident_gdtr[] = {0xff, 0xff, 0x00, 0x00, 0x7f, 0x00};
  daze_dos_memory_init(&memory, 0x3000, 0xa000);
  memset(guest + raw_ivt, 0, 4);
  memset(guest + k_dpmi_rm_gate_linear, 0, sizeof(raw_handler));
  memcpy(guest + 0x2000, resident_transition, sizeof(resident_transition));
  memcpy(guest + 0x2080, resident_gdtr, sizeof(resident_gdtr));
  if (!daze_kvm_child_context_capture(&resident, &machine, &layout, &dos, &memory, &dpmi)) goto out;
  memory = child_memory;
  daze_dos_process_state_init(&dos, 0x3000);
  dos.dos_vector_offset[0x2f] = 0x0020;
  dos.dos_vector_segment[0x2f] = 0x3000;
  if (short_ldt == 2) {
    dos.dos_vector_offset[0x2f] = 0;
    dos.dos_vector_segment[0x2f] = 0x3004;
  }
  dpmi.next_ldt_index = 0x31;
  dpmi.interrupt_vectors[0x2f] = (DazeDpmiInterruptVector){.offset = 0x1234, .segment = 0x0008};
  guest[0x30000] = 0x33;
  guest[0x30040] = 0x44;
  daze_write_u16(guest + raw_ivt, 0);
  daze_write_u16(guest + raw_ivt + 2, (uint16_t)(k_dpmi_rm_gate_linear >> 4));
  memcpy(guest + k_dpmi_rm_gate_linear, raw_handler, sizeof(raw_handler));
  if (resident_rejections(&resident, &machine, &dos, &memory, &dpmi)) goto out_resident;
  if (short_ldt == 1) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
    struct kvm_sregs sregs;
    if (ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) != 0) goto out_resident;
    sregs.ldt.limit = 0xff;
    if (ioctl(machine.vcpu, KVM_SET_SREGS, &sregs) != 0) goto out_resident;
    dos.dos_vector_segment[0x2f] = 0x3004;
    dos.dos_vector_offset[0x2f] = 0;
    result =
      daze_kvm_child_context_restore_resident(&resident, &machine, &dos, &memory, &dpmi, 8, NULL)
        ? 1
        : 0;
#endif
    goto out_resident;
  }
  const uint16_t retained_paragraphs = short_ldt == 2 ? 8 : 4;
  if (!daze_kvm_child_context_restore_resident(&resident, &machine, &dos, &memory, &dpmi,
                                               retained_paragraphs, &retained))
    goto out_resident;
  const uint16_t vector_segment = short_ldt == 2 ? 0x3004 : 0x3000;
  const uint16_t vector_offset = short_ldt == 2 ? 0 : 0x20;
  if (short_ldt == 2) {
    uint8_t projected[8];
    const DazeDosAllocation allocation = {.segment = 0x3000, .paragraphs = 8, .in_use = 1};
    if (!daze_raw_vector_projection_descriptor(&allocation, 0x3004, projected) ||
        memcmp(retained.ldt_bytes + 0x3000, projected, 8) != 0 ||
        !retained.raw_vector_projections[0].in_use ||
        retained.raw_vector_projections[0].selector != 0x3004)
      goto out_resident;
  }
  if (dos.dta_segment == 0x1234 && dos.dta_offset == 0x5678 &&
      memory.next_segment == 0x3000 + retained_paragraphs && memory.allocations[0].in_use &&
      memory.allocations[0].segment == 0x3000 &&
      memory.allocations[0].paragraphs == retained_paragraphs && guest[0x30000] == 0x33 &&
      guest[0x30040] == (short_ldt == 2 ? 0x44 : 0x22) && daze_read_u16(guest + raw_ivt) == 0 &&
      daze_read_u16(guest + raw_ivt + 2) == (uint16_t)(k_dpmi_rm_gate_linear >> 4) &&
      memcmp(guest + k_dpmi_rm_gate_linear, raw_handler, sizeof(raw_handler)) == 0 &&
      daze_read_u16(guest + 4 * 0x2f) == vector_offset &&
      daze_read_u16(guest + 4 * 0x2f + 2) == vector_segment &&
      dos.dos_vector_offset[0x2f] == vector_offset &&
      dos.dos_vector_segment[0x2f] == vector_segment && dpmi.next_ldt_index == 0x31 &&
      dpmi.interrupt_vectors[0x2f].offset == 0x1234 &&
      dpmi.interrupt_vectors[0x2f].segment == 0x0008 && retained.valid && retained.ldt_valid &&
      retained.ldt_bytes != NULL && retained.real_transition_valid &&
      retained.next_ldt_index == 0x31 && !resident.active && resident.parent_dpmi == NULL) {
    result = 0;
  }
out_resident:
  daze_kvm_resident_gdt_state_dispose(&retained);
  daze_kvm_resident_gdt_state_dispose(&retained);
  daze_kvm_child_context_dispose(&resident);
  daze_kvm_child_context_dispose(&resident);
out:
  daze_kvm_child_context_dispose(&context);
  daze_dos_process_state_dispose(&dos);
  daze_kvm_machine_destroy(&machine);
  return result;
}

int main(void) {
  const int result = run_case(0);
  if (result != 0) return result;
  if (snapshot_lifecycle(0) || snapshot_lifecycle(1)) return 1;
  const int short_result = run_case(1);
  return short_result != 0 ? short_result : run_case(2);
}
