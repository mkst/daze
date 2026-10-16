#include "guest_memory_layout.h"
#include "legacy_exception.h"
#include "machine_access.h"
#include "selector.h"
#include "exception_return_code.h"
#include <stdlib.h>
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
static int legacy_failure(DazeKvmMachine *m, int line) {
  struct kvm_regs r = {0};
  struct kvm_sregs s = {0};
  (void)ioctl(m->vcpu, KVM_GET_REGS, &r);
  (void)ioctl(m->vcpu, KVM_GET_SREGS, &s);
  fprintf(stderr, "legacy line=%d raw-exit=%u cs:ip=%04x:%llx ss:sp=%04x:%llx ax=%llx flags=%llx\n",
          line, ((struct kvm_run *)m->run)->exit_reason, s.cs.selector, (unsigned long long)r.rip,
          s.ss.selector, (unsigned long long)r.rsp, (unsigned long long)r.rax,
          (unsigned long long)r.rflags);
  return 1;
}
static int scenario(int mode, int fallback, unsigned sync) {
  DazeKvmMachine m;
  int status = daze_kvm_machine_init(&m, k_memory_size);
  if (status) return status;
  m.sync_regs_mask &= sync;
  ((struct kvm_run *)m.run)->kvm_valid_regs = (uint64_t)m.sync_regs_mask;
  if (fallback) m.immediate_exit_supported = 0;
  if ((mode == 10 || mode == 11 || mode >= 19) && !m.immediate_exit_supported) {
    daze_kvm_machine_destroy(&m);
    return 0;
  }
  DazeRunMetrics metrics = {.enabled = 1};
  m.run_metrics = &metrics;
  uint8_t *g = m.guest;
  daze_dpmi_descriptor_encode(g + GDT + DAZE_SEL_EXCEPTION_RETURN,
                              k_dpmi_exception_locked_stack_base,
                              k_memory_size - k_dpmi_exception_locked_stack_base - 1, 0x9a, 4);
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
  if (!daze_kvm_legacy_exception_install(&m, &gate)) return legacy_failure(&m, __LINE__);
  struct kvm_sregs s;
  struct kvm_regs r = {.rip = 0x15a,
                       .rsp = 0xffb6,
                       .rflags = 0x282,
                       .rax = 0x2c01,
                       .rbx = 0x8707,
                       .rsi = 0x96,
                       .rdi = 0x23,
                       .rbp = 0xffc8};
  if (ioctl(m.vcpu, KVM_GET_SREGS, &s) < 0) return legacy_failure(&m, __LINE__);
  s.cr0 = 0x11;
  s.gdt.base = GDT;
  s.gdt.limit = 0xffff;
  s.idt.base = IDT;
  s.idt.limit = 0x7ff;
  s.ldt =
    (struct kvm_segment){.selector = 0x30, .base = LDT, .limit = 0xffff, .type = 2, .present = 1};
  s.cs = segment(0xb4, 0x61000, 0x5540, 11);
  s.ds = s.es = s.ss = segment(0x124, 0x72000, 0xffff, 3);
  if (ioctl(m.vcpu, KVM_SET_SREGS, &s) < 0 || ioctl(m.vcpu, KVM_SET_REGS, &r) < 0)
    return legacy_failure(&m, __LINE__);
  DazeKvmDpmiEntryResult b;
  if (daze_kvm_dpmi_entry_continue_once(&m, &b) != 0) return legacy_failure(&m, __LINE__);
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
  struct kvm_run *run = m.run;
  if (mode == 10) run->immediate_exit = 1;
  if (mode == 11) run->kvm_dirty_regs = KVM_SYNC_X86_REGS;
  int handled = daze_kvm_legacy_exception_boundary(&m, &gate, &process, &state, &b);
  if (mode == 1 || mode == 2 || mode == 10 || mode == 11) {
    int pass = handled == -1 && state.depth == 0 && memcmp(before, g + 0xfd0ff0, 16) == 0;
    if (mode == 10 || mode == 11)
      pass = pass && run->immediate_exit == (mode == 10) &&
             run->kvm_dirty_regs == (mode == 11 ? KVM_SYNC_X86_REGS : 0);
    daze_kvm_machine_destroy(&m);
    return pass ? 0 : 1;
  }
  uint8_t frame[] = {0x5f, 1, 0xb4, 0, 0xd4, 0, 0x5a, 1, 0xb4, 0, 0x82, 2, 0xb6, 0xff, 0x24, 1};
  if (metrics.kvm_io_drain_calls != (unsigned)m.immediate_exit_supported ||
      metrics.kvm_io_drain_failures)
    return legacy_failure(&m, __LINE__);
  if (mode == 5 || mode == 6) frame[0] = mode == 5 ? 0x5b : 0x5d;
  if (mode == 8) frame[0] = 0x5e;
  if (mode == 9) frame[0] = 0x5d;
  const int native = daze_kvm_legacy_exception_guest_return(&state);
  if (native) {
    daze_write_u16(frame, k_kvm_exception_return_linear - k_dpmi_exception_locked_stack_base);
    daze_write_u16(frame + 2, DAZE_SEL_EXCEPTION_RETURN);
  }
  if (handled != 1 || b.cs != 8 || b.rip != 0x2f53 || b.ss != 0x48 || b.sp != 0xff0 ||
      b.ax != 0x2c01 || b.bx != 0x8707 || b.si != 0x96 || b.di != 0x23 || b.ds != 0x124 ||
      b.es != 0x124 || memcmp(g + 0xfd0ff0, frame, 16) != 0)
    return legacy_failure(&m, __LINE__);
  /* Handler changes AX; the bridge must preserve the handler's result. */
  const int demand_loaded = mode >= 4 && mode <= 6;
  if (demand_loaded) g[LDT + 0xd0 + 5] |= 0x80; /* Demand-loaded: retry the instruction. */
  if (mode >= 19) {
    if (daze_kvm_machine_drain_io(&m) != DAZE_KVM_MACHINE_OK ||
        ioctl(m.vcpu, KVM_GET_REGS, &r) < 0 || ioctl(m.vcpu, KVM_GET_SREGS, &s) < 0)
      return legacy_failure(&m, __LINE__);
    if (mode == 19) {
      memcpy(g + 0xfd0fe0, g + 0xfd0ff0, 4);
      r.rsp = 0xfe0;
    } else if (mode == 20) {
      memcpy(g + 0x72ff0, g + 0xfd0ff0, 4);
      s.ss = segment(0x124, 0x72000, 0xffff, 3);
    } else {
      size_t offset;
      for (offset = 0; offset + 2 < sizeof(exception_return_code); ++offset)
        if (exception_return_code[offset] == 0x2e && exception_return_code[offset + 1] == 0x0f &&
            exception_return_code[offset + 2] == 0xb2)
          break;
      if (offset + 2 >= sizeof(exception_return_code)) return legacy_failure(&m, __LINE__);
      g[k_kvm_exception_return_linear + offset] = 0x0f;
      g[k_kvm_exception_return_linear + offset + 1] = 0x0b;
    }
    if (ioctl(m.vcpu, KVM_SET_SREGS, &s) < 0 || ioctl(m.vcpu, KVM_SET_REGS, &r) < 0 ||
        daze_kvm_dpmi_entry_continue_once(&m, &b) != DAZE_KVM_DPMI_ENTRY_OK ||
        b.observation.raw_exit_reason != KVM_EXIT_SHUTDOWN)
      return legacy_failure(&m, __LINE__);
    (void)daze_kvm_legacy_exception_reconcile(&m, &state, &b);
    if (state.depth != 1 || metrics.kvm_exception_guest_returns ||
        metrics.kvm_exception_host_returns)
      return legacy_failure(&m, __LINE__);
    daze_kvm_machine_destroy(&m);
    return 0;
  }
  if (mode == 12) daze_write_u16(g + 0xfd0ff0 + 12, 3);
  if (mode == 13) daze_write_u16(g + 0xfd0ff0 + 10, 0x246);
  if (mode == 15) daze_kvm_legacy_exception_host_return(&m, &state);
  if (mode == 16) daze_dpmi_descriptor_encode(g + LDT + 0x120, 0x73000, 0xffff, 0x92, 0);
  if (mode == 17) {
    daze_dpmi_descriptor_encode(g + LDT + 0x128, 0x74000, 0xffff, 0x92, 0);
    daze_write_u16(g + 0xfd0ff0 + 14, 0x12c);
  }
  if (mode == 18 && native)
    daze_write_u32(g + k_kvm_exception_return_control + 20,
                   k_dpmi_exception_locked_stack_base - 0x8000);
  if (ioctl(m.vcpu, KVM_GET_REGS, &r) < 0) return legacy_failure(&m, __LINE__);
  r.rax = 0x1234;
  if (mode == 14) r.rflags |= 0x200000;
  if (ioctl(m.vcpu, KVM_SET_REGS, &r) < 0 || daze_kvm_dpmi_entry_continue_once(&m, &b) != 0)
    return legacy_failure(&m, __LINE__);
  if (daze_kvm_legacy_exception_boundary(&m, &gate, &process, &state, &b) < 0 || state.depth != 0 ||
      b.cs != (demand_loaded ? 0xd4 : 0xb4) || b.ss != (mode == 17 ? 0x12c : 0x124) ||
      (mode == 16 && b.ss_base != 0x73000) || (b.rflags & 0x200000) ||
      b.sp != (mode == 12  ? 3
               : mode == 6 ? 0xffc0
               : mode == 5 ? 0xffba
               : mode == 4 ? 0xffb2
                           : 0xffb6) ||
      b.ax != (demand_loaded ? 0x1255 : 0x1277) || b.es != 0x124 || b.es_base != 0x72000 ||
      (b.rflags & 0xffff) != (mode == 13 ? 0x246 : 0x282))
    return legacy_failure(&m, __LINE__);
  const int host_return = !native || mode == 12 || (mode >= 15 && mode <= 18);
  if (metrics.kvm_exception_guest_returns != (unsigned)!host_return ||
      metrics.kvm_exception_host_returns != (unsigned)host_return)
    return legacy_failure(&m, __LINE__);
  daze_kvm_machine_destroy(&m);
  return 0;
}
static DazeKvmMachine drain_machine;
static unsigned drain_number;
static void failure(int line) {
  struct kvm_regs r = {0};
  struct kvm_sregs s = {0};
  (void)ioctl(drain_machine.vcpu, KVM_GET_REGS, &r);
  (void)ioctl(drain_machine.vcpu, KVM_GET_SREGS, &s);
  fprintf(stderr,
          "drain case=%u line=%d raw-exit=%u cs:ip=%04x:%llx ax=%llx bx=%llx flags=%llx "
          "immediate=%u dirty=%llx\n",
          drain_number, line, ((struct kvm_run *)drain_machine.run)->exit_reason, s.cs.selector,
          (unsigned long long)r.rip, (unsigned long long)r.rax, (unsigned long long)r.rbx,
          (unsigned long long)r.rflags, ((struct kvm_run *)drain_machine.run)->immediate_exit,
          (unsigned long long)((struct kvm_run *)drain_machine.run)->kvm_dirty_regs);
  abort();
}
#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) failure(__LINE__);                                                                   \
  } while (0)

static void drain_case(int debug, int sync) {
  CHECK(daze_kvm_machine_init(&drain_machine, 0x10000) == DAZE_KVM_MACHINE_OK);
  if (!drain_machine.immediate_exit_supported) {
    fprintf(stderr, "KVM immediate-exit unsupported; legacy fallback is tested separately\n");
    daze_kvm_machine_destroy(&drain_machine);
    return;
  }
  DazeRunMetrics metrics = {.enabled = 1};
  drain_machine.run_metrics = &metrics;
  struct kvm_run *run = drain_machine.run;
  if (!sync) drain_machine.sync_regs_mask = run->kvm_valid_regs = 0;
  const unsigned char code[] = {
    0xb0, 0x01,                   /* mov al,1 */
    0xe6, 0xf4,                   /* out f4h,al */
    0x43,                         /* inc bx */
    0xc6, 0x06, 0x00, 0x01, 0x7a, /* mov byte [0100h],7ah */
    0xe6, 0xf4,                   /* out f4h,al */
    0xf4                          /* hlt */
  };
  memcpy(drain_machine.guest, code, sizeof(code));
  CHECK(daze_kvm_machine_set_real_mode(&drain_machine, 0, 0, 0, 0xfffe, 0, 0) ==
        DAZE_KVM_MACHINE_OK);
  struct kvm_guest_debug breakpoint = {0};
  if (debug) {
    breakpoint.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
    breakpoint.arch.debugreg[0] = 4;
    breakpoint.arch.debugreg[7] = 3;
    CHECK(daze_kvm_machine_set_guest_debug(&drain_machine, &breakpoint) == 0);
  }
  CHECK(daze_kvm_machine_run(&drain_machine) == 0);
  CHECK(run->exit_reason == KVM_EXIT_IO && run->io.port == 0xf4);
  struct kvm_regs expected, actual;
  CHECK(ioctl(drain_machine.vcpu, KVM_GET_REGS, &expected) == 0);
  expected.rip = 4;
  for (unsigned i = 0; i < 2; ++i) {
    CHECK(daze_kvm_machine_drain_io(&drain_machine) == DAZE_KVM_MACHINE_OK);
    CHECK(run->immediate_exit == 0);
    CHECK(metrics.kvm_io_drain_calls == i + 1 && metrics.kvm_io_drain_failures == 0);
    CHECK(ioctl(drain_machine.vcpu, KVM_GET_REGS, &actual) == 0);
    CHECK(memcmp(&expected, &actual, sizeof(actual)) == 0);
    CHECK(((unsigned char *)drain_machine.guest)[0x100] == 0);
  }
  if (debug) {
    CHECK(daze_kvm_machine_run(&drain_machine) == 0);
    CHECK(run->exit_reason == KVM_EXIT_DEBUG && run->debug.arch.pc == 4);
    CHECK(ioctl(drain_machine.vcpu, KVM_GET_REGS, &actual) == 0 && actual.rbx == expected.rbx);
    memset(&breakpoint, 0, sizeof(breakpoint));
    CHECK(daze_kvm_machine_set_guest_debug(&drain_machine, &breakpoint) == 0);
  }
  CHECK(daze_kvm_machine_run(&drain_machine) == 0);
  CHECK(run->exit_reason == KVM_EXIT_IO && run->io.port == 0xf4);
  CHECK(ioctl(drain_machine.vcpu, KVM_GET_REGS, &actual) == 0 && actual.rbx == expected.rbx + 1);
  CHECK(((unsigned char *)drain_machine.guest)[0x100] == 0x7a);
  daze_kvm_machine_destroy(&drain_machine);
  ++drain_number;
}

int main(void) {
  for (unsigned sync = 0; sync < 4; ++sync)
    for (int fallback = 0; fallback < 2; ++fallback) {
      for (int mode = 0; mode < 22; mode++) {
        if (mode == 7) continue;
        int status = scenario(mode, fallback, sync);
        if (status) {
          fprintf(stderr, "legacy scenario %d fallback=%d sync=%u failed\n", mode, fallback, sync);
          return status;
        }
      }
    }
  for (int debug = 0; debug < 2; ++debug)
    for (int sync = 0; sync < 2; ++sync)
      drain_case(debug, sync);
  return 0;
}
#else
int main(void) {
  return 77;
}
#endif
