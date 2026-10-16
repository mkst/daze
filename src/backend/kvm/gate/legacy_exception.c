#include "interrupt_vector.h"
#include "legacy_exception.h"
#include "machine_access.h"
#include "descriptor.h"
#include "exception_frame.h"
#include "idt_gate.h"
#include "kvm_bytes.h"
#include "kvm_range.h"
#include "port.h"
#include "selector.h"
#include "guest_memory_layout.h"
#include <string.h>
#include <stdlib.h>
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>

enum { LOCKED_BASE = k_dpmi_exception_locked_stack_base, CAPTURE_OFFSET = 0x400 };
static int guest_range(const DazeKvmMachine *machine, uint64_t address, size_t size) {
  return address <= UINT32_MAX && daze_kvm_range_fits(machine->guest_size, (uint32_t)address, size);
}
static int read_segment(const DazeKvmMachine *m, const struct kvm_sregs *s, uint16_t selector,
                        struct kvm_segment *segment) {
  uint32_t offset = selector & ~7u;
  uint64_t table = (selector & 4u) ? s->ldt.base : s->gdt.base;
  uint32_t limit = (selector & 4u) ? s->ldt.limit : s->gdt.limit;
  if (offset == 0 || offset + 7 > limit || ((selector & 4u) && !s->ldt.present) ||
      !guest_range(m, table + offset, 8))
    return 0;
  const uint8_t *d = (const uint8_t *)m->guest + table + offset;
  uint32_t size = daze_read_u16(d) | ((uint32_t)(d[6] & 15) << 16);
  if (d[6] & 0x80) size = (size << 12) | 0xfff;
  *segment = (struct kvm_segment){.base = (uint32_t)d[2] | ((uint32_t)d[3] << 8) |
                                          ((uint32_t)d[4] << 16) | ((uint32_t)d[7] << 24),
                                  .limit = size,
                                  .selector = selector,
                                  .type = d[5] & 15,
                                  .present = d[5] >> 7,
                                  .dpl = (d[5] >> 5) & 3,
                                  .s = (d[5] >> 4) & 1,
                                  .db = (d[6] >> 6) & 1,
                                  .g = d[6] >> 7,
                                  .avl = (d[6] >> 4) & 1};
  return 1;
}
static int debug_return(DazeKvmMachine *m, uint32_t linear, int enabled) {
  struct kvm_guest_debug debug = {0};
  if (enabled) {
    debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
    debug.arch.debugreg[0] = linear;
    debug.arch.debugreg[7] = 3;
  }
  return daze_kvm_machine_set_guest_debug(m, &debug) == 0;
}
int daze_kvm_legacy_exception_install(DazeKvmMachine *m, const DazeKvmProtectedGateLayout *gate) {
  const uint8_t bytes[] = {
    0x66, 0x50,                      /* push ax */
    0xb0, DAZE_KVM_LEGACY_NP_MARKER, /* mov al, DAZE_KVM_LEGACY_NP_MARKER */
    0xe6, DAZE_PORT_GATE,            /* out 0xf4,al */
    0xf4                             /* hlt */
  };
  if (m == NULL || m->guest == NULL || gate == NULL || gate->handler_selector != 0x50 ||
      gate->legacy_np_capture_address != (uint64_t)gate->handler_address + CAPTURE_OFFSET ||
      gate->idt_limit < 11 * 8 + 7)
    return 0;
  uint32_t capture = gate->legacy_np_capture_address;
  if (!daze_kvm_range_fits(m->guest_size, capture, sizeof(bytes)) ||
      !daze_kvm_range_fits(m->guest_size, gate->idt_address + 11 * 8, 8))
    return 0;
  memcpy((uint8_t *)m->guest + capture, bytes, sizeof(bytes));
  daze_kvm_encode_idt_gate((uint8_t *)m->guest + gate->idt_address + 11 * 8, CAPTURE_OFFSET, 0x60,
                           0x86);
  return 1;
}
int daze_kvm_legacy_exception_rearm(DazeKvmMachine *m, const DazeKvmLegacyExceptionState *state) {
  if (m == NULL || state == NULL || state->depth > DAZE_KVM_LEGACY_MAX_DEPTH) return 0;
  return state->depth == 0 || debug_return(m, state->deliveries[state->depth - 1].return_linear, 1);
}
static int instruction(const DazeKvmMachine *m, const struct kvm_sregs *s, uint16_t cs, uint16_t ip,
                       uint16_t error, uint16_t *length) {
  struct kvm_segment code, target;
  if (!read_segment(m, s, cs, &code) || !code.present || !code.s || !(code.type & 8) || code.db ||
      ip > code.limit || !guest_range(m, code.base + ip, 5) ||
      !read_segment(m, s, error, &target) || target.present || !target.s)
    return 0;
  const uint8_t *p = (const uint8_t *)m->guest + code.base + ip;
  uint16_t operand = 0;
  if (p[0] == 0x9a) {
    *length = 5;
    operand = daze_read_u16(p + 3);
  } else if (p[0] == 0xff && p[1] == 0x1e) {
    uint16_t offset = daze_read_u16(p + 2);
    if ((uint32_t)offset + 3 > s->ds.limit || !guest_range(m, s->ds.base + offset, 4)) return 0;
    *length = 4;
    operand = daze_read_u16((const uint8_t *)m->guest + s->ds.base + offset + 2);
  } else if (p[0] == 0x26 && p[1] == 0xc4 && p[2] == 0x3f) {
    struct kvm_regs r;
    if (ioctl(m->vcpu, KVM_GET_REGS, &r) < 0) return 0;
    uint16_t offset = (uint16_t)r.rbx;
    if ((uint32_t)offset + 3 > s->es.limit || !guest_range(m, s->es.base + offset, 4)) return 0;
    *length = 3;
    operand = daze_read_u16((const uint8_t *)m->guest + s->es.base + offset + 2);
  } else if (p[0] == 0xcb || p[0] == 0xca) {
    /* The original far-return frame follows our AX save and hardware frame. */
    struct kvm_regs r;
    if (ioctl(m->vcpu, KVM_GET_REGS, &r) < 0) return 0;
    uint16_t sp = (uint16_t)(r.rsp + 10);
    if ((uint32_t)sp + 3 > s->ss.limit || !guest_range(m, s->ss.base + sp, 4)) return 0;
    *length = p[0] == 0xcb ? 1 : 3;
    operand = daze_read_u16((const uint8_t *)m->guest + s->ss.base + sp + 2);
  } else
    return 0;
  return operand == error && (uint32_t)ip + *length <= code.limit;
}
int daze_kvm_legacy_exception_boundary(DazeKvmMachine *m, const DazeKvmProtectedGateLayout *gate,
                                       const DazeDpmiProcessState *process,
                                       DazeKvmLegacyExceptionState *state,
                                       DazeKvmDpmiEntryResult *b) {
  struct kvm_sregs s;
  struct kvm_regs r;
  if (m == NULL || gate == NULL || process == NULL || state == NULL || b == NULL ||
      state->depth > DAZE_KVM_LEGACY_MAX_DEPTH)
    return -1;
  int capture = b->observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
                b->observation.pio_port == DAZE_PORT_GATE &&
                b->observation.pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
                b->observation.pio_size == 1 && b->observation.pio_count == 1 &&
                b->observation.pio_value_present &&
                b->observation.pio_value == DAZE_KVM_LEGACY_NP_MARKER &&
                b->cs_base + b->rip == gate->handler_address + CAPTURE_OFFSET + 4;
  int returning = state->depth && b->observation.raw_exit_reason == KVM_EXIT_DEBUG &&
                  b->cs_base + b->rip == state->deliveries[state->depth - 1].return_linear &&
                  b->ss == DAZE_SEL_LOCKED_STACK &&
                  b->sp == state->deliveries[state->depth - 1].frame_sp + 4;
  if (!capture && !returning) return 0;
  if (daze_kvm_machine_get_sregs(m, &s) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_get_regs(m, &r) != DAZE_KVM_MACHINE_OK)
    return -1;
  if (returning) {
    DazeKvmLegacyExceptionDelivery *d = &state->deliveries[state->depth - 1];
    const uint8_t *frame = (const uint8_t *)m->guest + d->frame_linear;
    struct kvm_segment stack, target;
    if (!read_segment(m, &s, daze_read_u16(frame + 14), &stack) || !stack.present || !stack.s ||
        (stack.type & 8) || !(stack.type & 2))
      return -1;
    if (read_segment(m, &s, d->selector, &target) && target.present)
      r.rip = daze_read_u16(frame + 6);
    s.ss = stack;
    r.rsp = daze_read_u16(frame + 12);
    if (r.rsp > stack.limit) return -1;
    r.rflags = daze_read_u16(frame + 10) | 2;
    --state->depth;
    if (!debug_return(m, 0, 0)) return -1;
  } else {
    if (state->depth == DAZE_KVM_LEGACY_MAX_DEPTH || s.ss.db || s.cs.selector != 0x60 ||
        s.cs.base != gate->handler_address || !s.cs.db ||
        !guest_range(m, s.gdt.base + DAZE_SEL_LOCKED_STACK, 8))
      return -1;
    uint16_t sp = (uint16_t)r.rsp;
    if (sp > 0xfff5 || (uint32_t)sp + 9 > s.ss.limit || !guest_range(m, s.ss.base + sp, 10))
      return -1;
    const uint8_t *cpu = (const uint8_t *)m->guest + s.ss.base + sp;
    uint16_t ax = daze_read_u16(cpu), error = daze_read_u16(cpu + 2), ip = daze_read_u16(cpu + 4),
             cs = daze_read_u16(cpu + 6), flags = daze_read_u16(cpu + 8), length = 0;
    struct kvm_segment handler, code;
    uint16_t handler_cs = process->exception_vector_segment[11],
             handler_ip = process->exception_vector_offset[11];
    if (!instruction(m, &s, cs, ip, error, &length) || !read_segment(m, &s, handler_cs, &handler) ||
        !handler.present || !handler.s || !(handler.type & 8) || handler.db ||
        handler_ip > handler.limit || !guest_range(m, handler.base + handler_ip, 1) ||
        !read_segment(m, &s, cs, &code))
      return -1;
    uint16_t frame_sp = (uint16_t)(0xff0 - state->depth * 0x20);
    DazeDpmiExceptionFrameInput input = {.frame = {(uint16_t)(ip + length), cs, error, ip, cs,
                                                   flags, (uint16_t)(sp + 10), s.ss.selector},
                                         .locked_stack_base = LOCKED_BASE,
                                         .locked_stack_sp = frame_sp,
                                         .guest_range_limit = (uint32_t)m->guest_size - 1};
    uint32_t linear;
    uint8_t frame[16];
    if (!daze_dpmi_exception_frame_build(&input, &linear, frame)) return -1;
    /* Complete KVM's deferred OUT before replacing its interrupted CPU state. */
    if (m->immediate_exit_supported) {
      const int status = daze_kvm_machine_drain_io(m);
      if (status != DAZE_KVM_MACHINE_OK) {
        fprintf(stderr, "KVM legacy capture drain failed: status=%d error=%d\n", status, errno);
        return -1;
      }
    } else {
      DazeKvmDpmiEntryResult retired;
      if (daze_kvm_dpmi_entry_continue_to_linear(m, gate->handler_address + CAPTURE_OFFSET + 6,
                                                 &retired) != 0)
        return -1;
    }
    memcpy((uint8_t *)m->guest + linear, frame, 16);
    daze_dpmi_descriptor_encode((uint8_t *)m->guest + s.gdt.base + DAZE_SEL_LOCKED_STACK,
                                LOCKED_BASE, 0xfff, 0x92, 0);
    s.cs = handler;
    s.ss = (struct kvm_segment){.selector = DAZE_SEL_LOCKED_STACK,
                                .base = LOCKED_BASE,
                                .limit = 0xfff,
                                .type = 3,
                                .present = 1,
                                .s = 1};
    r.rax = (r.rax & ~0xffffull) | ax;
    r.rsp = frame_sp;
    r.rip = handler_ip;
    r.rflags = (flags & ~0x200u) | 2;
    state->deliveries[state->depth++] = (DazeKvmLegacyExceptionDelivery){
      linear, code.base + (uint16_t)(ip + length), frame_sp, error};
    if (getenv("DAZE_KVM_LEGACY_TRACE"))
      fprintf(stderr, "legacy-np: %04x:%04x error=%04x -> %04x:%04x depth=%zu\n", cs, ip, error,
              handler_cs, handler_ip, state->depth);
  }
  daze_kvm_machine_debug_invalidate(m);
  if (daze_kvm_machine_set_sregs(m, &s) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_set_regs(m, &r) != DAZE_KVM_MACHINE_OK ||
      !daze_kvm_legacy_exception_rearm(m, state))
    return -1;
  return daze_kvm_dpmi_entry_continue_once(m, b) == 0 ? 1 : -1;
}
#else
int daze_kvm_legacy_exception_install(DazeKvmMachine *m, const DazeKvmProtectedGateLayout *g) {
  (void)m;
  (void)g;
  return 0;
}
int daze_kvm_legacy_exception_rearm(DazeKvmMachine *m, const DazeKvmLegacyExceptionState *s) {
  (void)m;
  (void)s;
  return 0;
}
int daze_kvm_legacy_exception_boundary(DazeKvmMachine *m, const DazeKvmProtectedGateLayout *g,
                                       const DazeDpmiProcessState *p,
                                       DazeKvmLegacyExceptionState *s, DazeKvmDpmiEntryResult *b) {
  (void)m;
  (void)g;
  (void)p;
  (void)s;
  (void)b;
  return -1;
}
#endif
