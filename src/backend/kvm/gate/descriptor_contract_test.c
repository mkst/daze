#include "protected.h"
#include "rm_procedure.h"
#include "rm_entry.h"
#include "descriptor.h"
#include "request.h"
#include "kvm_bytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static unsigned case_number;
static struct kvm_run *current_run;
static DazeKvmMachine *current_machine;

static void dump_registers(void) {
  struct kvm_regs r;
  struct kvm_sregs s;
  if (current_machine == NULL || ioctl(current_machine->vcpu, KVM_GET_REGS, &r) != 0 ||
      ioctl(current_machine->vcpu, KVM_GET_SREGS, &s) != 0)
    return;
  fprintf(stderr,
          "cs:ip=%04x:%llx ss:sp=%04x:%llx ds/es/fs/gs=%04x/%04x/%04x/%04x flags=%llx cr0=%llx\n"
          "ax/bx/cx/dx=%llx/%llx/%llx/%llx si/di/bp=%llx/%llx/%llx gdt=%llx:%x ldt=%llx:%x\n",
          s.cs.selector, (unsigned long long)r.rip, s.ss.selector, (unsigned long long)r.rsp,
          s.ds.selector, s.es.selector, s.fs.selector, s.gs.selector, (unsigned long long)r.rflags,
          (unsigned long long)s.cr0, (unsigned long long)r.rax, (unsigned long long)r.rbx,
          (unsigned long long)r.rcx, (unsigned long long)r.rdx, (unsigned long long)r.rsi,
          (unsigned long long)r.rdi, (unsigned long long)r.rbp, (unsigned long long)s.gdt.base,
          s.gdt.limit, (unsigned long long)s.ldt.base, s.ldt.limit);
  fprintf(stderr, "ds/es/fs/gs/ss bases=%llx/%llx/%llx/%llx/%llx limits=%x/%x/%x/%x/%x\n",
          (unsigned long long)s.ds.base, (unsigned long long)s.es.base,
          (unsigned long long)s.fs.base, (unsigned long long)s.gs.base,
          (unsigned long long)s.ss.base, s.ds.limit, s.es.limit, s.fs.limit, s.gs.limit,
          s.ss.limit);
}
#define CHECK(condition)                                                                           \
  do {                                                                                             \
    if (!(condition)) {                                                                            \
      fprintf(stderr, "descriptor case=%u line=%d exit=%u\n", case_number, __LINE__,               \
              current_run == NULL ? 0 : current_run->exit_reason);                                 \
      dump_registers();                                                                            \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

static struct kvm_segment segment(uint16_t selector, uint32_t base, uint32_t limit, int code,
                                  int db) {
  return (struct kvm_segment){.selector = selector,
                              .base = base,
                              .limit = limit,
                              .type = code ? 11 : 3,
                              .present = 1,
                              .s = 1,
                              .db = db,
                              .g = limit > 0xfffff};
}

static int run_case(uint16_t function, uint32_t operand, uint16_t rights, unsigned kind) {
  DazeKvmMachine machine = {0};
  int status = daze_kvm_machine_init(&machine, 0x1000000);
  if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  CHECK(status == DAZE_KVM_MACHINE_OK);
  current_run = machine.run;
  current_machine = &machine;
  uint8_t *guest = machine.guest;
  DazeRunMetrics metrics = {.enabled = 1};
  machine.run_metrics = &metrics;
  const DazeKvmProtectedGateLayout layout = {.idt_address = 0xfdf800,
                                             .idt_limit = 0x7ff,
                                             .handler_address = 0xfde800,
                                             .dos_handler_address = 0xfde900,
                                             .default_dos_stub_address = 0xfde9c8,
                                             .record_address = 0xfdea00,
                                             .mailbox_address = 0xfdea40,
                                             .handler_selector = 0x50,
                                             .handler_data_selector = 0x58,
                                             .interrupt_gate_type = 0x8e,
                                             .exchange_limit = 1,
                                             .rm_entry_address = 0x5000};
  DazeKvmProtectedGateArtifacts artifacts;
  CHECK(daze_kvm_protected_gate_build(&layout, &artifacts));
  CHECK(daze_kvm_machine_write(&machine, layout.handler_address, artifacts.handler,
                               artifacts.handler_size));
  CHECK(daze_kvm_machine_write(&machine, layout.idt_address + 0x31 * 8, artifacts.idt_entry, 8));
  if (kind == 9 || kind == 14) CHECK(setenv("DAZE_KVM_GUEST_DESCRIPTORS", "0", 1) == 0);
  const size_t ldt_size = kind == 10 ? 0x80 : kind == 16 ? 16 : 0x10000;
  CHECK(daze_kvm_rm_entry_install(&machine, artifacts.rm_entry_epilogue, 0xfe0000, ldt_size));
  CHECK(unsetenv("DAZE_KVM_GUEST_DESCRIPTORS") == 0);
  daze_write_u32(guest + 0x5800, 1);
  const uint16_t selector = kind == 7    ? 0x10
                            : kind == 12 ? 0xfffc
                            : kind == 13 ? 4
                            : kind == 15 ? 0x87
                            : kind == 16 ? 0x0c
                                         : 0x84;
  uint8_t *descriptor = guest + 0xfe0000 + (selector & 0xfff8);
  daze_dpmi_descriptor_encode(descriptor, 0x50000, 0xffff, kind == 8 || kind == 14 ? 0x13 : 0x93,
                              0);
  uint8_t original[8];
  memcpy(original, descriptor, 8);
  const DazeDpmiRequest request = {
    .function = function, .selector = selector, .operand = operand, .rights = rights};
  DazeDpmiResult expected;
  if (function == 7)
    daze_dpmi_request_set_segment_base(&request, descriptor, &expected);
  else if (function == 8)
    daze_dpmi_request_set_segment_limit(&request, descriptor, &expected);
  else
    daze_dpmi_request_set_access_rights(&request, descriptor, &expected);
  const int success = expected.success && kind != 7 && kind != 9 && kind != 10 && kind != 13 &&
                      kind != 14 && kind != 17;
  daze_dpmi_descriptor_encode(guest + 0xff0008, 0, 0xfffff, 0x9b, 0xc);
  daze_dpmi_descriptor_encode(guest + 0xff0010, 0, 0xffff, 0x93, 0);
  daze_dpmi_descriptor_encode(guest + 0xff0030, kind == 11 ? 0x6000 : 0xfe0000, 0xffff, 0x82, 0);
  daze_dpmi_descriptor_encode(guest + 0xff0050, 0, 0xfffff, 0x9b, 0xc);
  daze_dpmi_descriptor_encode(guest + 0xff0058, 0, 0xfffff, 0x93, 0xc);
  const uint8_t client[] = {0xcd, 0x31, 0xe6, 0x77, 0xf4}; /* int 31h; out 77h,al; hlt */
  memcpy(guest + 0x8000, client, sizeof(client));
  struct kvm_sregs before;
  CHECK(ioctl(machine.vcpu, KVM_GET_SREGS, &before) == 0);
  before.cr0 = 0x11;
  before.cr3 = before.cr4 = before.efer = 0;
  if (kind == 17) {
    before.cr0 |= UINT64_C(0x80000000);
    before.cr3 = 0xe00000;
    before.cr4 = 0x10;
    for (unsigned i = 0; i < 4; ++i)
      daze_write_u32(guest + 0xe00000 + i * 4, (i << 22) | 0x83);
  }
  before.gdt.base = 0xff0000;
  before.gdt.limit = 0xffff;
  before.idt.base = layout.idt_address;
  before.idt.limit = layout.idt_limit;
  before.ldt = (struct kvm_segment){.selector = 0x30,
                                    .base = kind == 11 ? 0x6000 : 0xfe0000,
                                    .limit = 0xffff,
                                    .type = 2,
                                    .present = 1};
  before.cs = segment(8, 0, UINT32_MAX, 1, 1);
  before.ds = before.es = before.gs = before.ss = segment(0x10, 0, 0xffff, 0, 0);
  before.fs = segment(0x58, 0, UINT32_MAX, 0, 1);
  if (kind == 1) before.ds = segment(0x84, 0x50000, 0xffff, 0, 0);
  if (kind == 2) before.es = segment(0x84, 0x50000, 0xffff, 0, 0);
  if (kind == 3 || kind == 8 || kind == 14) before.fs = segment(0x84, 0x50000, 0xffff, 0, 0);
  if (kind == 4) before.gs = segment(0x84, 0x50000, 0xffff, 0, 0);
  if (kind == 5) before.ss = segment(0x84, 0x50000, 0xffff, 0, 0);
  const struct kvm_regs initial = {.rax = 0x11220000 | function,
                                   .rbx = 0x33440000 | selector,
                                   .rcx = 0x55660000 | (function == 9 ? rights : operand >> 16),
                                   .rdx = 0x77880000 | (operand & 0xffff),
                                   .rsi = 0x9999aaaa,
                                   .rdi = 0xbbbbcccc,
                                   .rbp = 0xdddd1111,
                                   .rsp = kind == 6 ? 0x20 : 0x9000,
                                   .rip = 0x8000,
                                   .rflags = 0xad7};
  CHECK(ioctl(machine.vcpu, KVM_SET_SREGS, &before) == 0);
  CHECK(ioctl(machine.vcpu, KVM_SET_REGS, &initial) == 0);
  CHECK(ioctl(machine.vcpu, KVM_RUN, 0) == 0);
  struct kvm_regs actual;
  struct kvm_sregs after;
  CHECK(ioctl(machine.vcpu, KVM_GET_REGS, &actual) == 0);
  CHECK(ioctl(machine.vcpu, KVM_GET_SREGS, &after) == 0);
  if (current_run->exit_reason != KVM_EXIT_IO || current_run->io.port != (success ? 0x77 : 0xf4))
    fprintf(stderr, "cs:ip=%04x:%llx ax=%llx bx=%llx ss:sp=%04x:%llx cr0=%llx\n", after.cs.selector,
            (unsigned long long)actual.rip, (unsigned long long)actual.rax,
            (unsigned long long)actual.rbx, after.ss.selector, (unsigned long long)actual.rsp,
            (unsigned long long)after.cr0);
  CHECK(current_run->exit_reason == KVM_EXIT_IO);
  CHECK(current_run->io.port == (success ? 0x77 : 0xf4));
  CHECK(memcmp(descriptor, success ? expected.descriptor : original, 8) == 0);
  CHECK(daze_read_u32(guest + layout.record_address) == initial.rax);
  if (kind == 14) CHECK(after.fs.selector == 0x58);
  if (success) {
    CHECK(actual.rax == initial.rax && actual.rbx == initial.rbx && actual.rcx == initial.rcx &&
          actual.rdx == initial.rdx && actual.rsi == initial.rsi && actual.rdi == initial.rdi &&
          actual.rbp == initial.rbp && actual.rsp == initial.rsp);
    CHECK(actual.rflags == (initial.rflags & ~UINT64_C(1)));
    if (kind == 1 && function == 7) CHECK(after.ds.base == operand);
    if (kind == 3 && function == 7) CHECK(after.fs.base == operand);
    if (kind == 2) CHECK(after.es.base == before.es.base);
    if (kind == 4) CHECK(after.gs.base == before.gs.base);
    if (kind == 5) CHECK(after.ss.base == before.ss.base);
    CHECK(daze_read_u32(guest + 0x5800) == 0);
  }
  daze_kvm_rm_entry_sync_metrics(&machine);
  for (unsigned i = 0; i < 3; ++i)
    CHECK(metrics.kvm_guest_descriptor_calls[i] == (uint64_t)(success && i == function - 7u));
  daze_kvm_rm_entry_sync_metrics(&machine);
  CHECK(metrics.kvm_guest_descriptor_calls[function - 7u] == (uint64_t)success);
  current_run = NULL;
  current_machine = NULL;
  daze_kvm_machine_destroy(&machine);
  case_number++;
  return 0;
}

int main(void) {
  CHECK(unsetenv("DAZE_KVM_GUEST_DESCRIPTORS") == 0);
  for (unsigned kind = 0; kind < 18; ++kind) {
    int status = run_case(kind == 8 || kind == 14 ? 9 : 7, 0x76543210, 0x93, kind);
    if (status) return status;
  }
  const uint32_t limits[] = {0, 0x7f, 0xffff, 0xfffff, 0x100000, 0x100fff, UINT32_MAX};
  for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); ++i) {
    int status = run_case(8, limits[i], 0, 0);
    if (status) return status;
  }
  const uint16_t rights[] = {0x93, 0xc093, 0xc09b, 0xc097, 0xd09b, 0x82, 0xf3, 0x99, 0x9f, 0x13};
  for (size_t i = 0; i < sizeof(rights) / sizeof(rights[0]); ++i) {
    int status = run_case(9, 0, rights[i], 0);
    if (status) return status;
  }
  return 0;
}
#else
int main(void) {
  return 77;
}
#endif
