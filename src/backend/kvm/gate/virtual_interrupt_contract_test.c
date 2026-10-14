#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include "protected.c"
#include "child_context.h"
#include "descriptor.h"
#include "machine_access.h"
#include "kvm_bytes.h"
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      fprintf(stderr, "check line=%d width=%x initial=%d sync=%d exit=%u\n", __LINE__, width,      \
              initial, sync, (m.run ? ((struct kvm_run *)m.run)->exit_reason : 0));                \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

static int run_case(unsigned width, int initial, int sync) {
  DazeKvmMachine m = {0};
  const int status = daze_kvm_machine_init(&m, 0x10000);
  if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  CHECK(status == DAZE_KVM_MACHINE_OK);
  DazeRunMetrics metrics = {.enabled = 1};
  m.run_metrics = &metrics;
  if (!sync) m.sync_regs_mask = 0;
  uint8_t *guest = m.guest;
  const DazeKvmProtectedGateLayout layout = {
    .idt_address = 0x2000,
    .idt_limit = 0x3ff,
    .handler_address = 0x3000,
    .dos_handler_address = 0x3100,
    .default_dos_stub_address = 0x31c8,
    .record_address = 0x4000,
    .mailbox_address = 0x4040,
    .handler_selector = 8,
    .handler_data_selector = 0x10,
    .interrupt_gate_type = width,
    .exchange_limit = 1,
    .virtual_handler_address = 0x3500,
    .virtual_control_address = 0x402c,
  };
  DazeKvmProtectedGateArtifacts a;
  CHECK(daze_kvm_protected_gate_build(&layout, &a));
  memcpy(guest + layout.handler_address, a.handler, a.handler_size);
  memcpy(guest + layout.virtual_handler_address, a.virtual_handler, a.virtual_handler_size);
  memcpy(guest + layout.idt_address + 0x31 * 8, a.idt_entry, 8);
  guest[layout.virtual_control_address] = initial;
  daze_dpmi_descriptor_encode(guest + 0x1008, 0, 0xfffff, 0x9a, 0x0c);
  daze_dpmi_descriptor_encode(guest + 0x1010, 0, 0xfffff, 0x92, 0x0c);
  daze_dpmi_descriptor_encode(guest + 0x1018, 0x100, 0xfffff, 0x92, 0x0c);
  const unsigned functions[] = {0x0900, 0x0900, 0x0901, 0x0901};
  size_t pos = 0x100;
  for (unsigned i = 0; i < 4; i++) {
    guest[pos++] = 0x66;
    guest[pos++] = 0xb8; /* mov ax,imm16 */
    daze_write_u16(guest + pos, functions[i]);
    pos += 2;
    guest[pos++] = 0xcd;
    guest[pos++] = 0x31; /* int 31h */
    guest[pos++] = 0xe6;
    guest[pos++] = 0x77; /* out 77h,al */
  }
  guest[pos] = 0xf4; /* hlt */
  struct kvm_sregs sr;
  CHECK(ioctl(m.vcpu, KVM_GET_SREGS, &sr) == 0);
  sr.cr0 = 0x11;
  sr.gdt.base = 0x1000;
  sr.gdt.limit = 0x1f;
  sr.idt.base = 0x2000;
  sr.idt.limit = 0x3ff;
  sr.cs = (struct kvm_segment){.selector = 8,
                               .base = 0,
                               .limit = 0xffffffff,
                               .type = 0xb,
                               .present = 1,
                               .s = 1,
                               .db = 1,
                               .g = 1};
  sr.ss = sr.ds = (struct kvm_segment){.selector = 0x10,
                                       .base = 0,
                                       .limit = 0xffffffff,
                                       .type = 3,
                                       .present = 1,
                                       .s = 1,
                                       .db = 1,
                                       .g = 1};
  sr.fs = sr.es = sr.gs = sr.ds;
  sr.fs.selector = sr.es.selector = sr.gs.selector = 0x18;
  sr.fs.base = sr.es.base = sr.gs.base = 0x100;
  struct kvm_regs r = {.rip = 0x100,
                       .rsp = 0x9000,
                       .rflags = 0xed7,
                       .rax = 0xaabb1234,
                       .rbx = 0x11223344,
                       .rcx = 0x22334455,
                       .rdx = 0x33445566,
                       .rsi = 0x44556677,
                       .rdi = 0x55667788,
                       .rbp = 0x66778899};
  const struct kvm_regs before = r;
  CHECK(ioctl(m.vcpu, KVM_SET_SREGS, &sr) == 0);
  CHECK(ioctl(m.vcpu, KVM_SET_REGS, &r) == 0);
  const unsigned previous[] = {initial, 0, 0, 1};
  for (unsigned i = 0; i < 4; i++) {
    CHECK(ioctl(m.vcpu, KVM_RUN, 0) == 0);
    const struct kvm_run *run = m.run;
    CHECK(run->exit_reason == KVM_EXIT_IO && run->io.port == 0x77);
    CHECK(ioctl(m.vcpu, KVM_GET_REGS, &r) == 0 && ioctl(m.vcpu, KVM_GET_SREGS, &sr) == 0);
    if (r.rax != (0xaabb0900u | previous[i]) || r.rflags != 0xed6)
      fprintf(stderr, "actual eax=%llx flags=%llx state=%u\n", (unsigned long long)r.rax,
              (unsigned long long)r.rflags, guest[layout.virtual_control_address]);
    CHECK(r.rax == (0xaabb0900u | previous[i]) && r.rflags == 0xed6);
    CHECK(r.rbx == before.rbx && r.rcx == before.rcx && r.rdx == before.rdx &&
          r.rsi == before.rsi && r.rdi == before.rdi && r.rbp == before.rbp && r.rsp == before.rsp);
    CHECK(sr.fs.selector == 0x18 && sr.fs.base == 0x100 && sr.es.selector == 0x18 &&
          sr.ds.selector == 0x10 && sr.gs.selector == 0x18);
    CHECK(guest[layout.virtual_control_address] == (functions[i] & 1));
  }
  CHECK(daze_read_u32(guest + layout.virtual_control_address + 4) == 2);
  CHECK(daze_read_u32(guest + layout.virtual_control_address + 12) == 2);
  int host_state = 0;
  DazeDpmiLinearMemory linear;
  daze_dpmi_linear_memory_init(&linear, 0x5000, 0x8000);
  DazeKvmDpmiMediator mediator = {.guest = guest,
                                  .guest_size = m.guest_size,
                                  .record_address = layout.record_address,
                                  .mailbox_address = layout.mailbox_address,
                                  .virtual_interrupts_enabled = &host_state,
                                  .linear_memory = &linear,
                                  .ldt_address = 0x6000,
                                  .ldt_size = 8};
  DazeKvmDpmiEntryResult boundary = {.observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                                                     .pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT,
                                                     .pio_size = 1,
                                                     .pio_count = 1,
                                                     .pio_value_present = 1,
                                                     .pio_port = 0xf4,
                                                     .pio_value = 0x31}};
  DazeKvmProtectedGateExchange exchange;
  daze_write_u32(guest + layout.record_address + 32, 8);
  daze_write_u32(guest + layout.record_address + 36, 0xed7);
  daze_write_u32(guest + layout.record_address, 0xaabb0900);
  CHECK(process_mediator_boundary_impl(&m, &mediator, &layout, &boundary, &exchange));
  CHECK(host_state == 0 && guest[layout.virtual_control_address] == 0 &&
        daze_read_u32(guest + layout.mailbox_address) == 0xaabb0901);
  daze_write_u32(guest + layout.record_address, 0xaabb0901);
  CHECK(process_mediator_boundary_impl(&m, &mediator, &layout, &boundary, &exchange));
  CHECK(host_state == 1 && guest[layout.virtual_control_address] == 1 &&
        daze_read_u32(guest + layout.mailbox_address) == 0xaabb0900);
  CHECK(metrics.kvm_guest_virtual_interrupt_calls[0] == 2 &&
        metrics.kvm_guest_virtual_interrupt_calls[1] == 2);
  CHECK(ioctl(m.vcpu, KVM_RUN, 0) == 0 && ((struct kvm_run *)m.run)->exit_reason == KVM_EXIT_HLT);
  DazeKvmChildContext child = {0};
  DazeKvmRunnerRequestCommon process = {.psp_segment = 0x100, .load_segment = 0x110};
  DazeDosProcessState dos;
  DazeDosMemory memory;
  DazeDpmiProcessState dpmi = {0};
  daze_dos_process_state_init(&dos, 0x100);
  daze_dos_memory_init(&memory, 0x3000, 0x8000);
  guest[layout.virtual_control_address] = 0;
  CHECK(
    daze_kvm_protected_gate_sync_virtual_interrupts(&m, &layout, &dpmi.virtual_interrupts_enabled));
  CHECK(daze_kvm_child_context_capture(&child, &m, &process, &dos, &memory, &dpmi));
  daze_dos_process_state_init(&dos, 0x200);
  daze_dos_memory_init(&memory, 0x3000, 0x8000);
  dpmi.virtual_interrupts_enabled = 1;
  memcpy(guest + layout.virtual_control_address, a.virtual_control, sizeof(a.virtual_control));
  daze_write_u32(guest + layout.virtual_control_address + 4, UINT32_MAX);
  r.rip = 0x100;
  CHECK(ioctl(m.vcpu, KVM_SET_REGS, &r) == 0 && ioctl(m.vcpu, KVM_RUN, 0) == 0);
  CHECK(((struct kvm_run *)m.run)->exit_reason == KVM_EXIT_IO);
  CHECK(
    daze_kvm_protected_gate_sync_virtual_interrupts(&m, &layout, &dpmi.virtual_interrupts_enabled));
  CHECK(dpmi.virtual_interrupts_enabled == 0 &&
        metrics.kvm_guest_virtual_interrupt_calls[0] == UINT64_C(0x100000002));
  guest[0x108] = 0xf4; /* hlt */
  CHECK(ioctl(m.vcpu, KVM_RUN, 0) == 0 && ((struct kvm_run *)m.run)->exit_reason == KVM_EXIT_HLT);
  CHECK(daze_kvm_child_context_restore(&child, &m, &dos, &memory, &dpmi));
  guest = m.guest;
  CHECK(
    daze_kvm_protected_gate_sync_virtual_interrupts(&m, &layout, &dpmi.virtual_interrupts_enabled));
  CHECK(dpmi.virtual_interrupts_enabled == 0 && guest[layout.virtual_control_address] == 0);
  CHECK(metrics.kvm_guest_virtual_interrupt_calls[0] == UINT64_C(0x100000002) &&
        metrics.kvm_guest_virtual_interrupt_calls[1] == 2);
  daze_dos_process_state_dispose(&dos);
  daze_kvm_machine_destroy(&m);
  return 0;
}

int main(void) {
  for (unsigned w = 0; w < 2; w++)
    for (int i = 0; i < 2; i++)
      for (int s = 0; s < 2; s++) {
        const int result = run_case(w ? 0x8e : 0x86, i, s);
        if (result != 0) return result;
      }
  puts("virtual interrupt contracts: eight cases passed");
  return 0;
}

#else
int main(void) {
  return 77;
}
#endif
