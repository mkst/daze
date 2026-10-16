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
#include "exception_return_code.h"
#include "exception_delivery_code.h"
#include <string.h>
#include <stdlib.h>

enum {
  RETURN_OFFSET = k_kvm_exception_return_linear - k_dpmi_exception_locked_stack_base,
  RETURN_OUT_OFFSET = RETURN_OFFSET + sizeof(exception_return_code) - 3
};
enum {
  DELIVERY_ENABLED = 0,
  DELIVERY_LDTR = 4,
  DELIVERY_HANDLER = 6,
  DELIVERY_HANDLER_CS = 10,
  DELIVERY_HANDLER_DESCRIPTOR = 12,
  DELIVERY_STACK = 20,
  DELIVERY_STACK_CS = 24,
  DELIVERY_CLIENT_SS = 26,
  DELIVERY_ENTERED = 28,
  DELIVERY_ACTIVE = 32,
  DELIVERY_HOST_RETURNS = 36,
  DELIVERY_REPORTED = 40,
  DELIVERY_FLAGS = 44,
  DELIVERY_FALLBACK = 48,
  DELIVERY_STACK_DESCRIPTOR = 56,
  DELIVERY_MAGIC = 76,
  DELIVERY_OBSERVED = 80,
  DELIVERY_RETURN_LINEAR = 88,
  DELIVERY_CONTROL_SIZE = 92,
  DELIVERY_MAGIC_VALUE = 0x4e50444c
};
_Static_assert(RETURN_OFFSET == 0xee00 &&
                 k_kvm_exception_return_control - k_dpmi_exception_locked_stack_base == 0xf100 &&
                 k_dpmi_exception_locked_stack_sp == 0xff0 && DAZE_KVM_LEGACY_MAX_DEPTH == 1,
               "exception-return assembly layout");
_Static_assert(k_kvm_exception_delivery_linear == 0xfdd000 &&
                 k_kvm_exception_delivery_control == 0xfdd800 && k_dpmi_gdt_address == 0xff0000 &&
                 k_dpmi_ldt_address == 0xfe0000 && DAZE_SEL_GATE_CODE == 0x50 &&
                 DAZE_SEL_GATE_DATA == 0x58 && DAZE_SEL_LOCKED_STACK == 0x48 &&
                 DAZE_SEL_EXCEPTION_RETURN == 0xa0 && DELIVERY_CONTROL_SIZE <= 0x200,
               "exception-delivery assembly layout");

static uint8_t *delivery_control(const DazeKvmMachine *m) {
  if (!m || !m->guest || m->guest_size != k_memory_size ||
      !daze_kvm_range_fits(m->guest_size, k_kvm_exception_delivery_control, DELIVERY_CONTROL_SIZE))
    return NULL;
  uint8_t *data = (uint8_t *)m->guest + k_kvm_exception_delivery_control;
  return daze_read_u32(data + DELIVERY_MAGIC) == DELIVERY_MAGIC_VALUE ? data : NULL;
}

static int delivery_boundary(DazeKvmMachine *m, DazeKvmLegacyExceptionState *state,
                             const DazeKvmDpmiEntryResult *b) {
  uint8_t *data = delivery_control(m);
  if (!data) return 1;
  if ((b->cs == DAZE_SEL_GATE_CODE && b->rip >= k_kvm_exception_delivery_linear &&
       b->rip < k_kvm_exception_delivery_control) ||
      daze_read_u32(data + DELIVERY_ACTIVE) > 1)
    return 0;
  if (b->observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO && b->observation.pio_value_present &&
      b->observation.pio_value == DAZE_KVM_LEGACY_NP_MARKER) {
    uint64_t address = (uint64_t)b->ss_base + b->sp;
    if (address <= UINT32_MAX && daze_kvm_range_fits(m->guest_size, (uint32_t)address, 10)) {
      uint16_t cs = daze_read_u16((uint8_t *)m->guest + address + 6);
      if (cs == DAZE_SEL_GATE_CODE || cs == DAZE_SEL_EXCEPTION_RETURN) return 0;
    }
  }
  uint8_t *frame =
    (uint8_t *)m->guest + k_dpmi_exception_locked_stack_base + k_dpmi_exception_locked_stack_sp;
  int active = daze_read_u32(data + DELIVERY_ACTIVE) != 0;
  int completed = b->observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
                  b->ss != DAZE_SEL_LOCKED_STACK && b->cs != DAZE_SEL_EXCEPTION_RETURN &&
                  daze_read_u32(frame) == 0;
  unsigned pending = active && !completed;
  if (pending) {
    if (state->depth && !daze_kvm_legacy_exception_guest_return(state)) return 0;
    if (state->depth && !state->deliveries[0].guest_delivery && m->run_metrics &&
        m->run_metrics->enabled)
      m->run_metrics->kvm_exception_guest_returns++;
    const uint8_t *control = (const uint8_t *)m->guest + k_kvm_exception_return_control;
    state->deliveries[0] = (DazeKvmLegacyExceptionDelivery){
      .frame_linear = k_dpmi_exception_locked_stack_base + k_dpmi_exception_locked_stack_sp,
      .frame_sp = k_dpmi_exception_locked_stack_sp,
      .return_linear = daze_read_u32(data + DELIVERY_RETURN_LINEAR),
      .selector = daze_read_u16(control + 4),
      .return_ip = daze_read_u16(control),
      .return_cs = daze_read_u16(control + 2),
      .native_return = 1,
      .guest_delivery = 1};
    state->depth = 1;
  }
  if (b->observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_PIO)
    return !active || b->observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG;
  uint32_t entered = daze_read_u32(data + DELIVERY_ENTERED);
  uint32_t finished = entered - pending - daze_read_u32(data + DELIVERY_HOST_RETURNS);
  /* Guest-only batches can wrap the counters; deltas intentionally use modulo 2^32. */
  if (m->run_metrics && m->run_metrics->enabled) {
    m->run_metrics->kvm_exception_guest_deliveries +=
      (uint32_t)(entered - daze_read_u32(data + DELIVERY_OBSERVED));
    m->run_metrics->kvm_exception_guest_returns +=
      (uint32_t)(finished - daze_read_u32(data + DELIVERY_REPORTED));
  }
  daze_write_u32(data + DELIVERY_OBSERVED, entered);
  daze_write_u32(data + DELIVERY_REPORTED, finished);
  return 1;
}

int daze_kvm_legacy_exception_guest_return(const DazeKvmLegacyExceptionState *state) {
  return state && state->depth == 1 && state->deliveries[0].native_return;
}

void daze_kvm_legacy_exception_host_return(DazeKvmMachine *machine,
                                           const DazeKvmLegacyExceptionState *state) {
  if (daze_kvm_legacy_exception_guest_return(state) && machine && machine->guest &&
      daze_kvm_range_fits(machine->guest_size, k_kvm_exception_return_control, 40))
    daze_write_u32((uint8_t *)machine->guest + k_kvm_exception_return_control + 28, 0);
}

static int return_marker(const DazeKvmDpmiEntryResult *b) {
  return b->observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
         b->observation.pio_port == DAZE_PORT_GATE &&
         b->observation.pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
         b->observation.pio_size == 1 && b->observation.pio_count == 1 &&
         b->observation.pio_value_present &&
         b->observation.pio_value == DAZE_KVM_LEGACY_RETURN_MARKER &&
         b->cs == DAZE_SEL_EXCEPTION_RETURN && b->cs_base == k_dpmi_exception_locked_stack_base &&
         b->rip == RETURN_OUT_OFFSET;
}

int daze_kvm_legacy_exception_reconcile(DazeKvmMachine *m, DazeKvmLegacyExceptionState *state,
                                        const DazeKvmDpmiEntryResult *b) {
  if (!m || !state || !b || state->depth > DAZE_KVM_LEGACY_MAX_DEPTH) return 0;
  if (!delivery_boundary(m, state, b)) return 0;
  if (!daze_kvm_legacy_exception_guest_return(state)) return 1;
  const DazeKvmLegacyExceptionDelivery *d = &state->deliveries[0];
  if (!m->guest || !daze_kvm_range_fits(m->guest_size, d->frame_linear, 16)) return 0;
  if (b->cs == DAZE_SEL_EXCEPTION_RETURN) return return_marker(b);
  /* A fault in the final stack switch/IRET must not become a new client delivery. */
  if (b->observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO && b->observation.pio_value_present &&
      b->observation.pio_value == DAZE_KVM_LEGACY_NP_MARKER) {
    uint64_t address = (uint64_t)b->ss_base + b->sp;
    if (address > UINT32_MAX || !daze_kvm_range_fits(m->guest_size, (uint32_t)address, 10) ||
        daze_read_u16((const uint8_t *)m->guest + address + 6) == DAZE_SEL_EXCEPTION_RETURN)
      return 0;
  }
  if (b->observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO && b->ss != DAZE_SEL_LOCKED_STACK &&
      daze_read_u32((const uint8_t *)m->guest + d->frame_linear) == 0) {
    state->depth = 0;
    if (!d->guest_delivery && m->run_metrics && m->run_metrics->enabled)
      m->run_metrics->kvm_exception_guest_returns++;
  }
  return 1;
}
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

static int prepare_guest_return(DazeKvmMachine *m, const struct kvm_sregs *s, uint16_t ip,
                                uint16_t cs, uint16_t target) {
  struct kvm_segment code, stack;
  if (!m->immediate_exit_supported || m->guest_size != k_memory_size ||
      s->gdt.base != k_dpmi_gdt_address || s->ldt.base != k_dpmi_ldt_address ||
      ((s->efer & (1u << 10)) || (s->cr0 & (1u << 31))) ||
      !read_segment(m, s, DAZE_SEL_EXCEPTION_RETURN, &code) || code.base != LOCKED_BASE ||
      code.limit != k_memory_size - LOCKED_BASE - 1 || !code.present || !code.s ||
      (code.type & 14) != 10 || !code.db || code.dpl ||
      !read_segment(m, s, s->ss.selector, &stack) || stack.base != s->ss.base ||
      stack.limit != s->ss.limit || stack.db != s->ss.db || stack.db ||
      (stack.type & 14) != (s->ss.type & 14) || !stack.present || !stack.s || stack.dpl ||
      stack.base > m->guest_size || s->ss.selector & 3)
    return 0;
  uint64_t address = ((s->ss.selector & 4) ? s->ldt.base : s->gdt.base) + (s->ss.selector & ~7u);
  if (address < LOCKED_BASE || !guest_range(m, address, 8)) return 0;
  uint8_t *control = (uint8_t *)m->guest + k_kvm_exception_return_control;
  memset(control, 0, 40);
  daze_write_u16(control, ip);
  daze_write_u16(control + 2, cs);
  daze_write_u16(control + 4, target);
  daze_write_u16(control + 6, s->ss.selector);
  daze_write_u32(control + 8, (uint32_t)(address - LOCKED_BASE));
  memcpy(control + 12, (const uint8_t *)m->guest + address, 8);
  control[17] &= (uint8_t)~1u;
  daze_write_u32(control + 20, (uint32_t)stack.base);
  daze_write_u32(control + 24, LOCKED_BASE);
  daze_write_u32(control + 28, 1);
  daze_write_u16(control + 32, s->gdt.limit);
  daze_write_u32(control + 34, (uint32_t)s->gdt.base);
  daze_write_u16(control + 38, s->ldt.selector);
  return 1;
}

static int flat_segment(const DazeKvmMachine *m, const struct kvm_sregs *s, uint16_t selector,
                        unsigned type) {
  struct kvm_segment segment;
  return read_segment(m, s, selector, &segment) && !segment.base && segment.limit == UINT32_MAX &&
         segment.present && segment.s && segment.db && !segment.dpl && (segment.type & 14) == type;
}

static void prepare_guest_delivery(DazeKvmMachine *m, const struct kvm_sregs *s,
                                   uint16_t handler_cs, uint16_t handler_ip, int native) {
  uint8_t *data = delivery_control(m);
  if (!data) return;
  daze_write_u32(data + DELIVERY_ENABLED, 0);
  daze_write_u32(data + DELIVERY_ACTIVE, 0);
  struct kvm_segment ldt;
  if (!native || s->gdt.limit != 0xffff || !s->ldt.present || s->ldt.limit != 0xffff ||
      (uint64_t)s->ss.base + s->ss.limit >= LOCKED_BASE || (s->ldt.selector & 7) ||
      !read_segment(m, s, s->ldt.selector, &ldt) || ldt.s || ldt.type != 2 || !ldt.present ||
      ldt.base != s->ldt.base || ldt.limit != s->ldt.limit ||
      !flat_segment(m, s, DAZE_SEL_GATE_CODE, 10) || !flat_segment(m, s, DAZE_SEL_GATE_DATA, 2) ||
      getenv("DAZE_KVM_LEGACY_TRACE"))
    return;
  const uint8_t *control = (const uint8_t *)m->guest + k_kvm_exception_return_control;
  uint64_t table = (handler_cs & 4) ? s->ldt.base : s->gdt.base;
  daze_write_u16(data + DELIVERY_LDTR, s->ldt.selector);
  daze_write_u32(data + DELIVERY_HANDLER, handler_ip);
  daze_write_u16(data + DELIVERY_HANDLER_CS, handler_cs);
  memcpy(data + DELIVERY_HANDLER_DESCRIPTOR, (const uint8_t *)m->guest + table + (handler_cs & ~7u),
         8);
  data[DELIVERY_HANDLER_DESCRIPTOR + 5] |= 1;
  daze_write_u32(data + DELIVERY_STACK, LOCKED_BASE + 0xf00);
  daze_write_u16(data + DELIVERY_STACK_CS, DAZE_SEL_GATE_DATA);
  daze_write_u16(data + DELIVERY_CLIENT_SS, s->ss.selector);
  memcpy(data + DELIVERY_STACK_DESCRIPTOR, control + 12, 8);
  daze_write_u32(data + DELIVERY_ENABLED, 1);
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
  int native = m->guest_size == k_memory_size && m->immediate_exit_supported;
  if (!daze_kvm_range_fits(m->guest_size, capture, native ? 15 : sizeof(bytes)) ||
      !daze_kvm_range_fits(m->guest_size, gate->idt_address + 11 * 8, 8))
    return 0;
  memcpy((uint8_t *)m->guest + capture, bytes, sizeof(bytes));
  _Static_assert(sizeof(exception_return_code) <= 0x300, "return code stays below control");
  if (daze_kvm_range_fits(m->guest_size, k_kvm_exception_return_linear,
                          k_kvm_exception_return_size))
    memcpy((uint8_t *)m->guest + k_kvm_exception_return_linear, exception_return_code,
           sizeof(exception_return_code));
  _Static_assert(sizeof(exception_delivery_code) <= 0x800, "delivery code stays below control");
  if (native) {
    uint8_t *entry = (uint8_t *)m->guest + capture;
    const uint8_t jump[] = {0xeb, 0x06, /* jmp short +6 */
                            0xea};      /* jmp ptr16:32 */
    memcpy(entry, jump, 2);
    entry[8] = jump[2];
    daze_write_u32(entry + 9, k_kvm_exception_delivery_linear);
    daze_write_u16(entry + 13, DAZE_SEL_GATE_CODE);
    memcpy((uint8_t *)m->guest + k_kvm_exception_delivery_linear, exception_delivery_code,
           sizeof(exception_delivery_code));
    uint8_t *data = delivery_control(m);
    if (!data) {
      data = (uint8_t *)m->guest + k_kvm_exception_delivery_control;
      memset(data, 0, DELIVERY_CONTROL_SIZE);
      daze_write_u32(data + DELIVERY_MAGIC, DELIVERY_MAGIC_VALUE);
    }
    daze_write_u32(data + DELIVERY_ENABLED, 0);
    daze_write_u32(data + DELIVERY_FALLBACK, CAPTURE_OFFSET + 2);
    daze_write_u16(data + DELIVERY_FALLBACK + 4, DAZE_SEL_GATE_ALIAS);
  }
  daze_kvm_encode_idt_gate((uint8_t *)m->guest + gate->idt_address + 11 * 8, CAPTURE_OFFSET, 0x60,
                           0x86);
  return 1;
}
int daze_kvm_legacy_exception_rearm(DazeKvmMachine *m, const DazeKvmLegacyExceptionState *state) {
  if (m == NULL || state == NULL || state->depth > DAZE_KVM_LEGACY_MAX_DEPTH) return 0;
  return state->depth == 0 || daze_kvm_legacy_exception_guest_return(state) ||
         debug_return(m, state->deliveries[state->depth - 1].return_linear, 1);
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
  uint8_t *data = delivery_control(m);
  if (data && (daze_read_u32(data + DELIVERY_HANDLER) != process->exception_vector_offset[11] ||
               daze_read_u16(data + DELIVERY_HANDLER_CS) != process->exception_vector_segment[11]))
    daze_write_u32(data + DELIVERY_ENABLED, 0);
  if (!daze_kvm_legacy_exception_reconcile(m, state, b)) return -1;
  const int native_return = daze_kvm_legacy_exception_guest_return(state) && return_marker(b) &&
                            b->ss == DAZE_SEL_LOCKED_STACK &&
                            b->sp == state->deliveries[0].frame_sp + 2;
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
  returning |= native_return;
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
    if (native_return) {
      r.rax = (r.rax & ~0xffffull) |
              daze_read_u16((const uint8_t *)m->guest + s.ss.base + (uint16_t)r.rsp);
      r.rip = d->return_ip;
      if (read_segment(m, &s, d->selector, &target) && target.present)
        r.rip = daze_read_u16(frame + 6);
      if (!read_segment(m, &s, d->return_cs, &s.cs) ||
          daze_kvm_machine_drain_io(m) != DAZE_KVM_MACHINE_OK)
        return -1;
    }
    s.ss = stack;
    r.rsp = daze_read_u16(frame + 12);
    if (r.rsp > stack.limit) return -1;
    r.rflags = daze_read_u16(frame + 10) | 2;
    if (data) {
      if (d->guest_delivery)
        daze_write_u32(data + DELIVERY_HOST_RETURNS,
                       daze_read_u32(data + DELIVERY_HOST_RETURNS) + 1);
      daze_write_u32(data + DELIVERY_ACTIVE, 0);
      daze_write_u32((uint8_t *)m->guest + d->frame_linear, 0);
    }
    --state->depth;
    if (!native_return && !debug_return(m, 0, 0)) return -1;
    if (m->run_metrics && m->run_metrics->enabled) m->run_metrics->kvm_exception_host_returns++;
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
    int native = prepare_guest_return(m, &s, (uint16_t)(ip + length), cs, error);
    prepare_guest_delivery(m, &s, handler_cs, handler_ip, native);
    if (native) {
      daze_write_u16(frame, RETURN_OFFSET);
      daze_write_u16(frame + 2, DAZE_SEL_EXCEPTION_RETURN);
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
    state->deliveries[state->depth++] =
      (DazeKvmLegacyExceptionDelivery){.frame_linear = linear,
                                       .return_linear = code.base + (uint16_t)(ip + length),
                                       .frame_sp = frame_sp,
                                       .selector = error,
                                       .return_ip = (uint16_t)(ip + length),
                                       .return_cs = cs,
                                       .native_return = native};
    if (m->run_metrics && m->run_metrics->enabled) m->run_metrics->kvm_exception_host_deliveries++;
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
