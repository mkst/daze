#include "guest_memory_layout.h"
#include "legacy_exception.h"
#include "descriptor.h"
#include "kvm_bytes.h"
#include <stdio.h>
#include <string.h>
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>
enum { GDT = 0xff0000, LDT = 0xfe0000, IDT = 0xfdf800, GATE = 0xfde800 };
static struct kvm_segment segment(uint16_t selector, uint32_t base, uint32_t limit, uint8_t type) {
  return (struct kvm_segment){
    .selector = selector, .base = base, .limit = limit, .type = type, .present = 1, .s = 1};
}
static int scenario(int mode) {
  DazeKvmMachine m;
  int status = daze_kvm_machine_init(&m, k_memory_size);
  if (status) return status;
  uint8_t *g = m.guest;
  daze_dpmi_descriptor_encode(g + GDT + 8, 0x108d0, 0xffff, 0x9a, 0);
  daze_dpmi_descriptor_encode(g + GDT + 0x60, GATE, 0xffff, 0x9a, 0x04);
  daze_dpmi_descriptor_encode(g + GDT + 0x30, LDT, 0xffff, 0x82, 0);
  daze_dpmi_descriptor_encode(g + LDT + 0xb0, 0x61000, 0x5540, 0x9a, 0);
  daze_dpmi_descriptor_encode(g + LDT + 0x120, 0x72000, 0xffff, 0x92, 0);
  daze_dpmi_descriptor_encode(g + LDT + 0xd0, 0x63000, 0xffff,
                              mode == 3   ? 0x9a
                              : mode == 9 ? 0x12
                                          : 0x1a,
                              0);
  const uint8_t call[] = {0x9a, 0, 0, 0xd4, 0, 0xb0, 0x77, 0xe6, 0xf4, 0xf4};
  memcpy(g + 0x6115a, call, sizeof(call));
  if (mode == 5 || mode == 6) {
    g[0x6115a] = mode == 5 ? 0xcb : 0xca;
    g[0x6115b] = 6;
    g[0x6115c] = 0;
    daze_write_u16(g + 0x81fb6, 0);
    daze_write_u16(g + 0x81fb8, 0xd4);
  }
  if (mode == 8) {
    const uint8_t indirect[] = {0xff, 0x1e, 0x20, 0}; /* call far [0020h] */
    memcpy(g + 0x6115a, indirect, sizeof(indirect));
    g[0x6115e] = 0xb0;
    g[0x6115f] = 0x77;
    g[0x61160] = 0xe6;
    g[0x61161] = 0xf4;
    daze_write_u16(g + 0x72020, 0);
    daze_write_u16(g + 0x72022, 0xd4);
  }
  if (mode == 9) {
    const uint8_t load[] = {0x26, 0xc4, 0x3f,        /* les di,es:[bx] */
                            0xb0, 0x77, 0xe6, 0xf4}; /* mov al,77h; out f4h,al */
    memcpy(g + 0x6115a, load, sizeof(load));
    daze_write_u16(g + 0x7a707, 0x1234);
    daze_write_u16(g + 0x7a709, 0xd4);
  }
  if (mode == 2) {
    g[0x6115a] = 0xcd;
    g[0x6115b] = 11;
  } /* Software INT is not #NP. */
  g[0x63000] = 0xb0;
  g[0x63001] = 0x55;
  g[0x63002] = 0xe6;
  g[0x63003] = 0xf4;
  /* Synthetic client handler first exposes its entry, then far-returns. */
  g[0x13823] = 0xe6;
  g[0x13824] = 0xf4;
  g[0x13825] = 0xcb;
  DazeKvmProtectedGateLayout gate = {.handler_selector = 0x50,
                                     .handler_address = GATE,
                                     .idt_address = IDT,
                                     .idt_limit = 0x7ff,
                                     .legacy_np_capture_address = GATE + 0x400};
  if (!daze_kvm_legacy_exception_install(&m, &gate)) return 1;
  struct kvm_sregs s;
  struct kvm_regs r = {.rip = 0x15a,
                       .rsp = 0xffb6,
                       .rflags = 0x282,
                       .rax = 0x2c01,
                       .rbx = 0x8707,
                       .rsi = 0x96,
                       .rdi = 0x23,
                       .rbp = 0xffc8};
  if (ioctl(m.vcpu, KVM_GET_SREGS, &s) < 0) return 1;
  s.cr0 = 0x11;
  s.gdt.base = GDT;
  s.gdt.limit = 0xffff;
  s.idt.base = IDT;
  s.idt.limit = 0x7ff;
  s.ldt =
    (struct kvm_segment){.selector = 0x30, .base = LDT, .limit = 0xffff, .type = 2, .present = 1};
  s.cs = segment(0xb4, 0x61000, 0x5540, 11);
  s.ds = s.es = s.ss = segment(0x124, 0x72000, 0xffff, 3);
  if (ioctl(m.vcpu, KVM_SET_SREGS, &s) < 0 || ioctl(m.vcpu, KVM_SET_REGS, &r) < 0) return 1;
  DazeKvmDpmiEntryResult b;
  if (daze_kvm_dpmi_entry_continue_once(&m, &b) != 0) return 1;
  DazeDpmiProcessState process = {0};
  DazeKvmLegacyExceptionState state = {0};
  process.exception_vector_segment[11] = mode == 1 ? 0 : 8;
  process.exception_vector_offset[11] = 0x2f53;
  if (mode == 3) {
    int pass =
      b.ax == 0x2c55 && daze_kvm_legacy_exception_boundary(&m, &gate, &process, &state, &b) == 0;
    daze_kvm_machine_destroy(&m);
    return pass ? 0 : 1;
  }
  uint8_t before[16];
  memcpy(before, g + 0xfd0ff0, 16);
  int handled = daze_kvm_legacy_exception_boundary(&m, &gate, &process, &state, &b);
  if (mode == 1 || mode == 2) {
    int pass = handled == -1 && state.depth == 0 && memcmp(before, g + 0xfd0ff0, 16) == 0;
    daze_kvm_machine_destroy(&m);
    return pass ? 0 : 1;
  }
  uint8_t frame[] = {0x5f, 1, 0xb4, 0, 0xd4, 0, 0x5a, 1, 0xb4, 0, 0x82, 2, 0xb6, 0xff, 0x24, 1};
  if (mode == 5 || mode == 6) frame[0] = mode == 5 ? 0x5b : 0x5d;
  if (mode == 8) frame[0] = 0x5e;
  if (mode == 9) frame[0] = 0x5d;
  if (handled != 1 || b.cs != 8 || b.rip != 0x2f53 || b.ss != 0x48 || b.sp != 0xff0 ||
      b.ax != 0x2c01 || b.bx != 0x8707 || b.si != 0x96 || b.di != 0x23 || b.ds != 0x124 ||
      b.es != 0x124 || memcmp(g + 0xfd0ff0, frame, 16) != 0)
    return 1;
  /* Handler changes AX; the bridge must preserve the handler's result. */
  const int demand_loaded = mode >= 4 && mode <= 6;
  if (demand_loaded) g[LDT + 0xd0 + 5] |= 0x80; /* Demand-loaded: retry the instruction. */
  if (ioctl(m.vcpu, KVM_GET_REGS, &r) < 0) return 1;
  r.rax = 0x1234;
  if (ioctl(m.vcpu, KVM_SET_REGS, &r) < 0 || daze_kvm_dpmi_entry_continue_once(&m, &b) != 0)
    return 1;
  if (daze_kvm_legacy_exception_boundary(&m, &gate, &process, &state, &b) != 1 ||
      state.depth != 0 || b.cs != (demand_loaded ? 0xd4 : 0xb4) || b.ss != 0x124 ||
      b.sp != (mode == 6   ? 0xffc0
               : mode == 5 ? 0xffba
               : mode == 4 ? 0xffb2
                           : 0xffb6) ||
      b.ax != (demand_loaded ? 0x1255 : 0x1277) || (b.rflags & 0xffff) != 0x282)
    return 1;
  daze_kvm_machine_destroy(&m);
  return 0;
}
int main(void) {
  for (int mode = 0; mode < 10; mode++) {
    if (mode == 7) continue;
    int status = scenario(mode);
    if (status) {
      fprintf(stderr, "legacy scenario %d failed\n", mode);
      return status;
    }
  }
  return 0;
}
#else
int main(void) {
  return 77;
}
#endif
