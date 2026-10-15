#include "rm_procedure.h"

#include "dpmi_error.h"
#include "dpmi_function.h"
#include "machine_access.h"
#include "request.h"
#include "rm_frame.h"
#include "kvm_bytes.h"
#include "kvm_range.h"
#include "monotonic_clock.h"
#include "runner_resume.h"
#include "runner_private.h"
#include "selector.h"
#include "guest_memory_layout.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rm_entry_code.h"
#include "rm_entry.h"
#include "write_batch.h"

int daze_kvm_rm_entry_install(DazeKvmMachine *machine, uint32_t epilogue, uint32_t ldt_address,
                              size_t ldt_size) {
  if (epilogue == 0) return 1;
  if (machine == NULL || ldt_size < 16 || ldt_size > 0x10000 || ldt_size % 8 != 0 ||
      !daze_kvm_range_fits(machine->guest_size, ldt_address, ldt_size))
    return 0;
  _Static_assert(sizeof(native_entry_code) <= DAZE_KVM_RM_ENTRY_CONTROL - DAZE_KVM_RM_ENTRY_LINEAR,
                 "entry code stays below control state");
  _Static_assert(sizeof(native_low_code) <= DAZE_KVM_RM_ENTRY_PARKED - DAZE_KVM_RM_ENTRY_LOW_LINEAR,
                 "low entry code stays below parked state");
  uint8_t control[DAZE_KVM_RM_ENTRY_CONTROL_SIZE] = {0};
  daze_kvm_rm_entry_sync_metrics(machine);
  daze_write_u32(control + 0x30, epilogue);
  daze_write_u32(control + 0x68, DAZE_KVM_RM_ENTRY_SIGNATURE);
  const char *setting = getenv("DAZE_KVM_GUEST_DESCRIPTORS");
  if (setting == NULL || strcmp(setting, "0") != 0) {
    /* The mediator targets its configured LDT, independently of the cached LDTR. */
    daze_write_u32(control + DAZE_KVM_RM_ENTRY_LDT_OFFSET, ldt_address);
    daze_write_u32(control + DAZE_KVM_RM_ENTRY_LDT_LAST_OFFSET, (uint32_t)ldt_size - 8);
  }
  setting = getenv("DAZE_KVM_GUEST_VECTORS");
  if (setting == NULL || strcmp(setting, "0") != 0)
    daze_write_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET, 1);
  return daze_kvm_machine_write(machine, DAZE_KVM_RM_ENTRY_LINEAR, native_entry_code,
                                sizeof(native_entry_code)) &&
         daze_kvm_machine_write(machine, DAZE_KVM_RM_ENTRY_LOW_LINEAR, native_low_code,
                                sizeof(native_low_code)) &&
         daze_kvm_machine_write(machine, DAZE_KVM_RM_ENTRY_CONTROL, control, sizeof(control));
}

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include "rm_return_code.h"
#include "descriptor.h"

static void dump_rejected_far_load(DazeKvmMachine *machine, const struct kvm_regs *uregs);

enum {
  RM_CONTINUE_PORT = 0x00,
  RM_GATE_PORT = 0x00f4,
  RM_PIC_PORT_1 = 0x21,
  RM_PIC_PORT_2 = 0xa1,
  RM_MAX_STEPS = 4096,
  /* Shared 0301h trampoline layout: selector 0028h has base 2000h;
   * the real-mode target far pointer is stored at CS:0160h. */
  RM_GATE_CS_BASE = 0x2000,
  RM_GATE_CS_SELECTOR = DAZE_SEL_GATE,
  RM_TRAMPOLINE_LINEAR = 0x2140,
  RM_TRAMPOLINE_IP = 0x0140,
  RM_TARGET_LINEAR = 0x2160,
};

typedef struct {
  struct kvm_regs regs;
  struct kvm_sregs sregs;
} ParkedState;

static struct kvm_segment protected_code_segment(uint16_t selector, uint32_t base);
static int return_bridge_eligible(const DazeKvmMachine *machine, const ParkedState *parked,
                                  uint32_t frame_address);

static void native_arm(DazeKvmMachine *machine, const ParkedState *parked, uint32_t frame_address) {
  if (!daze_kvm_rm_entry_installed(machine)) return;
  const struct kvm_sregs *s = &parked->sregs;
  uint8_t *guest = machine->guest;
  if (daze_read_u32(guest + 0x5830) == 0) return;
  daze_write_u32(guest + DAZE_KVM_RM_ENTRY_CONTROL, 0);
  if (s->cs.base != 0 || !s->cs.db || s->gdt.base != k_dpmi_gdt_address || s->gdt.limit != 0xffff ||
      s->ldt.base != k_dpmi_ldt_address || s->ldt.limit != 0xffff ||
      s->ss.selector != DAZE_SEL_DATA || s->ss.db || s->ss.limit != 0xffff ||
      s->ds.selector != DAZE_SEL_DATA || s->es.selector != DAZE_SEL_DATA ||
      s->fs.selector != DAZE_SEL_GATE_DATA || (s->gs.selector == 0 && !s->gs.unusable) ||
      memcmp(&s->ss, &s->ds, sizeof(s->ss)) || memcmp(&s->ss, &s->es, sizeof(s->ss)) ||
      daze_read_u16(guest + 0xfdea20) != DAZE_SEL_CODE ||
      (guest[k_dpmi_gdt_address + DAZE_SEL_CODE + 6] & 0x40) ||
      !return_bridge_eligible(machine, parked, frame_address))
    return;
  if (!daze_read_u32(guest + 0x5850)) {
    for (size_t i = DAZE_SEL_RM_SS; i <= DAZE_SEL_RM_STACK + 7; ++i)
      if (guest[k_dpmi_gdt_address + i]) return;
    daze_write_u32(guest + 0x5850, 1);
  }
  /* Real-mode loads retain cached attributes: establish 16-bit writable caches first. */
  for (unsigned sel = DAZE_SEL_RM_SS; sel <= DAZE_SEL_RM_GS; sel += 8)
    daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + sel, 0, 0xffff, 0x93, 0);
  daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + DAZE_SEL_RM_STACK,
                              k_dpmi_rm_return_bridge, 0xffff, 0x93, 0);
  daze_write_u32(guest + 0x5804, (uint32_t)s->es.base);
  const unsigned selectors[] = {DAZE_SEL_DATA, DAZE_SEL_CODE, DAZE_SEL_GATE, DAZE_SEL_GATE_CODE,
                                DAZE_SEL_GATE_DATA};
  for (size_t i = 0; i < 5; i++)
    memcpy(guest + 0x5808 + i * 8, guest + k_dpmi_gdt_address + selectors[i], 8);
  daze_write_u16(guest + 0x5834, s->gs.selector);
  if (s->gs.selector != 0) {
    const uint32_t descriptor =
      (uint32_t)((s->gs.selector & 4) ? s->ldt.base : s->gdt.base) + (s->gs.selector & ~7u);
    daze_write_u32(guest + 0x5838, descriptor);
    memcpy(guest + 0x5848, guest + descriptor, 8);
  }
  _Static_assert(sizeof(*s) <= DAZE_KVM_RM_ENTRY_CONTROL_SIZE - 0x100, "saved segment state fits");
  memcpy(guest + DAZE_KVM_RM_ENTRY_CONTROL + 0x100, s, sizeof(*s));
  daze_write_u16(guest + 0x5854, s->gdt.limit);
  daze_write_u32(guest + 0x5856, (uint32_t)s->gdt.base);
  daze_write_u16(guest + 0x585a, s->ldt.selector);
  daze_write_u16(guest + 0x585c, s->idt.limit);
  daze_write_u32(guest + 0x585e, (uint32_t)s->idt.base);
  daze_write_u32(guest + 0x5864, (uint32_t)s->cr0);
  daze_write_u32(guest + DAZE_KVM_RM_ENTRY_CONTROL, 1);
}

static int reloadable_segment(const DazeKvmMachine *machine, const struct kvm_sregs *sregs,
                              const struct kvm_segment *segment) {
  if (segment->selector == 0) return segment->unusable;
  if ((segment->selector & 3) || segment->unusable || !segment->present || !segment->s ||
      segment->dpl || segment->l || ((segment->type & 8) && !(segment->type & 2)))
    return 0;
  const uint32_t offset = segment->selector & ~7u;
  const int local = segment->selector & 4;
  const uint64_t base = local ? sregs->ldt.base : sregs->gdt.base;
  const uint32_t limit = local ? sregs->ldt.limit : sregs->gdt.limit;
  if ((local && (sregs->ldt.unusable || !sregs->ldt.present)) || offset + 7 > limit ||
      base > UINT32_MAX || !daze_kvm_range_fits(machine->guest_size, (uint32_t)base + offset, 8) ||
      base + offset > UINT32_MAX)
    return 0;
  const uint8_t *d = (const uint8_t *)machine->guest + base + offset;
  const uint32_t descriptor_base =
    daze_read_u16(d + 2) | ((uint32_t)d[4] << 16) | ((uint32_t)d[7] << 24);
  uint32_t descriptor_limit = daze_read_u16(d) | ((uint32_t)(d[6] & 15) << 16);
  if (d[6] & 0x80) descriptor_limit = (descriptor_limit << 12) | 0xfff;
  /* Loading a segment may set its accessed bit; the remaining cache must match. */
  return descriptor_base == segment->base && descriptor_limit == segment->limit &&
         (d[5] & 0xfe) == (0x90 | (segment->type & 0xe)) &&
         (d[6] >> 4) == (segment->avl | (segment->db << 2) | (segment->g << 3));
}

static int return_bridge_eligible(const DazeKvmMachine *machine, const ParkedState *parked,
                                  uint32_t frame_address) {
  const struct kvm_sregs *s = &parked->sregs;
  const struct kvm_regs *r = &parked->regs;
  if (r->r8 || r->r9 || r->r10 || r->r11 || r->r12 || r->r13 || r->r14 || r->r15) return 0;
  if (s->cs.selector != DAZE_SEL_GATE_CODE || (s->cs.type & 0xe) != 0xa ||
      (s->cr0 & 0x80000001u) != 1 || (r->rflags & ((1u << 8) | (1u << 16) | (1u << 17))) ||
      r->rsp < 4 || r->rsp > s->ss.limit || (!s->ss.db && r->rsp > UINT16_MAX) ||
      (s->ss.type & 0xe) != 2 || s->ss.base + r->rsp > machine->guest_size ||
      s->idt.base > UINT32_MAX || r->rip > s->cs.limit ||
      !daze_kvm_range_fits(machine->guest_size, frame_address, DAZE_DPMI_RM_FRAME_SIZE) ||
      daze_guest_ranges_overlap(frame_address, DAZE_DPMI_RM_FRAME_SIZE, k_dpmi_rm_return_bridge,
                                k_dpmi_rm_return_bridge_size) ||
      daze_guest_ranges_overlap(frame_address, DAZE_DPMI_RM_FRAME_SIZE,
                                (uint32_t)(s->ss.base + r->rsp - 4), 4))
    return 0;
  const uint64_t values[] = {r->rax, r->rbx, r->rcx,    r->rdx, r->rsi, r->rdi,
                             r->rbp, r->rsp, r->rflags, r->rip, s->cr0};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
    if (values[i] > UINT32_MAX) return 0;
  const struct kvm_segment gate = protected_code_segment(RM_GATE_CS_SELECTOR, RM_GATE_CS_BASE);
  const struct kvm_segment flat = {.selector = DAZE_SEL_GATE_DATA,
                                   .limit = UINT32_MAX,
                                   .type = 3,
                                   .present = 1,
                                   .s = 1,
                                   .db = 1,
                                   .g = 1};
  const struct kvm_segment *segments[] = {&s->cs, &s->ss, &s->ds, &s->es,
                                          &s->fs, &s->gs, &gate,  &flat};
  for (size_t i = 0; i < sizeof(segments) / sizeof(segments[0]); ++i)
    if (!reloadable_segment(machine, s, segments[i])) return 0;
  return 1;
}

static int install_return_bridge(DazeKvmMachine *machine, const ParkedState *parked,
                                 uint32_t frame_address) {
  if (!return_bridge_eligible(machine, parked, frame_address)) return 0;
  uint8_t state[0x70] = {0};
  const uint32_t values[] = {(uint32_t)parked->regs.rax,
                             (uint32_t)parked->regs.rbx,
                             (uint32_t)parked->regs.rcx,
                             (uint32_t)parked->regs.rdx,
                             (uint32_t)parked->regs.rsi,
                             (uint32_t)parked->regs.rdi,
                             (uint32_t)parked->regs.rbp,
                             (uint32_t)parked->regs.rsp,
                             (uint32_t)parked->regs.rflags,
                             (uint32_t)parked->sregs.cr0,
                             frame_address};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
    daze_write_u32(state + 4 * i, values[i]);
  const uint16_t selectors[] = {parked->sregs.ds.selector, parked->sregs.es.selector,
                                parked->sregs.fs.selector, parked->sregs.gs.selector,
                                parked->sregs.ss.selector};
  for (size_t i = 0; i < sizeof(selectors) / sizeof(selectors[0]); ++i)
    daze_write_u16(state + 0x2c + 2 * i, selectors[i]);
  daze_write_u16(state + 0x36, parked->sregs.idt.limit);
  daze_write_u32(state + 0x38, (uint32_t)parked->sregs.idt.base);
  daze_write_u32(state + 0x3c, (uint32_t)parked->regs.rip);
  daze_write_u16(state + 0x40, parked->sregs.cs.selector);
  const uint8_t gate[] = {0xea, 0, 0, 0x40, 0x02}; /* jmp far 0240h:0000h */
  if (!daze_kvm_range_fits(machine->guest_size, k_dpmi_rm_return_bridge,
                           k_dpmi_rm_return_bridge_size) ||
      !daze_kvm_machine_write(machine, k_dpmi_rm_return_bridge, rm_return_code,
                              sizeof(rm_return_code)) ||
      !daze_kvm_machine_write(machine, k_dpmi_rm_return_bridge + 0x600, state, sizeof(state)) ||
      !daze_kvm_machine_write(machine, DAZE_DPMI_RM_GATE_LINEAR, gate, sizeof(gate)))
    return -1;
  return 1;
}

static int timed_rm_kvm_run(DazeKvmMachine *machine) {
  DazeRunMetrics *const metrics = machine->run_metrics;
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const int status = daze_kvm_machine_run(machine);
  if (metrics != NULL && metrics->enabled) {
    const uint64_t finished = monotonic_nanoseconds();
    metrics->kvm_rm_procedure_run_calls++;
    if (finished >= started) metrics->kvm_rm_procedure_run_nanoseconds += finished - started;
  }
  return status;
}

static uint64_t elapsed_nanoseconds(uint64_t started, uint64_t finished) {
  return finished >= started ? finished - started : 0;
}

static void record_procedure_cost(DazeRunMetrics *metrics, uint64_t runner_calls,
                                  uint64_t date_calls, uint64_t time_calls,
                                  const DazeRunMetricsRmProcedureCost *cost) {
  /* Attribute a whole detour only when it serviced exactly one clock request.
   * Arbitrary far procedures may service multiple or unrelated boundaries. */
  const unsigned kind = runner_calls == 1 && date_calls == 1   ? DAZE_RUN_METRICS_RM_DATE
                        : runner_calls == 1 && time_calls == 1 ? DAZE_RUN_METRICS_RM_TIME
                                                               : DAZE_RUN_METRICS_RM_OTHER;
  DazeRunMetricsRmProcedureCost *entry = &metrics->kvm_rm_procedure_costs[kind];
  entry->calls++;
  entry->total_nanoseconds += cost->total_nanoseconds;
  entry->setup_nanoseconds += cost->setup_nanoseconds;
  entry->reflect_nanoseconds += cost->reflect_nanoseconds;
  entry->cleanup_nanoseconds += cost->cleanup_nanoseconds;
  entry->resume_nanoseconds += cost->resume_nanoseconds;
  entry->reflect_run_nanoseconds += cost->reflect_run_nanoseconds;
  entry->resume_run_nanoseconds += cost->resume_run_nanoseconds;
  entry->service_nanoseconds += cost->service_nanoseconds;
}

static void real_segment(struct kvm_segment *segment, uint16_t selector, uint8_t type) {
  *segment = (struct kvm_segment){0};
  segment->base = (uint32_t)selector << 4;
  segment->limit = 0xffff;
  segment->selector = selector;
  segment->type = type;
  segment->present = 1;
  segment->dpl = 0;
  segment->db = 0;
  segment->s = 1;
  segment->l = 0;
  segment->g = 0;
  segment->avl = 0;
  segment->unusable = 0;
}

static struct kvm_segment protected_code_segment(uint16_t selector, uint32_t base) {
  struct kvm_segment segment = {0};
  segment.base = base;
  segment.limit = 0xffff;
  segment.selector = selector;
  segment.type = 0x0a;
  segment.present = 1;
  segment.s = 1;
  return segment;
}

static int prepare_protected_return(DazeKvmMachine *machine, ParkedState *state,
                                    const struct kvm_sregs *returned) {
  if (state->sregs.cs.selector != DAZE_SEL_GATE_CODE || (state->sregs.cr0 & 0x80000001u) != 1 ||
      returned->cr0 != (state->sregs.cr0 & ~UINT64_C(1)) || state->regs.rax > UINT32_MAX ||
      state->regs.rip > UINT32_MAX || (state->regs.rflags & ((1u << 8) | (1u << 17))))
    return 0;
  /* Restoring CR0 through KVM resets the MMU even for PE-only changes.
   * Set PE in guest code; retain the parked data/stack descriptor caches. */
  uint8_t code[] = {
    0x66, 0xb8, 0,    0,    0,    0,       /* mov eax, protected_cr0 */
    0x0f, 0x22, 0xc0,                      /* mov cr0, eax */
    0x2e, 0x66, 0xa1, 0x00, 0x02,          /* mov eax, cs:[0200h] */
    0x66, 0xea, 0,    0,    0,    0, 0, 0, /* jmp far protected_cs:eip */
  };
  daze_write_u32(code + 2, (uint32_t)state->sregs.cr0);
  daze_write_u32(code + 16, (uint32_t)state->regs.rip);
  daze_write_u16(code + 20, state->sregs.cs.selector);
  uint8_t saved_eax[4];
  daze_write_u32(saved_eax, (uint32_t)state->regs.rax);
  if (!daze_kvm_machine_write(machine, k_pm_reentry_wrapper, code, sizeof(code)) ||
      !daze_kvm_machine_write(machine, k_pm_reentry_state, saved_eax, sizeof(saved_eax)))
    return -1;
  state->sregs.cr0 = returned->cr0;
  state->sregs.cs = protected_code_segment(RM_GATE_CS_SELECTOR, RM_GATE_CS_BASE);
  state->regs.rip = k_pm_reentry_wrapper - RM_GATE_CS_BASE;
  return 1;
}

static int enter_guest_transition(DazeKvmMachine *machine,
                                  const uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE],
                                  const DazeDpmiRmProcedure *rm, int preserve_eax,
                                  struct kvm_regs *regs, struct kvm_sregs *sregs) {
  /* The guest trampoline clears PE and far-jumps to reload real-mode CS. Data registers
   * contain the supplied real-mode values during this transition. */
  static const uint8_t trampoline[] = {
    0xfa,                         /* cli */
    0x0f, 0x20, 0xc0,             /* mov eax, cr0 */
    0x83, 0xe0, 0xfe,             /* and ax, 0fffeh */
    0x0f, 0x22, 0xc0,             /* mov cr0, eax */
    0x2e, 0xff, 0x2e, 0x60, 0x01, /* jmp far cs:[0160h] */
  };
  static const uint8_t eax_preserving_trampoline[] = {
    0xfa,                         /* cli */
    0x66, 0x50,                   /* push eax */
    0x0f, 0x20, 0xc0,             /* mov eax, cr0 */
    0x83, 0xe0, 0xfe,             /* and ax, 0fffeh */
    0x0f, 0x22, 0xc0,             /* mov cr0, eax */
    0x66, 0x58,                   /* pop eax */
    0x2e, 0xff, 0x2e, 0x60, 0x01, /* jmp far cs:[0160h] */
  };
  static const uint8_t gate[] = {
    0xf4, /* hlt */
  };
  const uint8_t target[4] = {(uint8_t)rm->target_ip, (uint8_t)(rm->target_ip >> 8),
                             (uint8_t)rm->target_cs, (uint8_t)(rm->target_cs >> 8)};
  const uint8_t *const trampoline_bytes = preserve_eax ? eax_preserving_trampoline : trampoline;
  const size_t trampoline_size =
    preserve_eax ? sizeof(eax_preserving_trampoline) : sizeof(trampoline);
  if (!daze_kvm_machine_write(machine, RM_TRAMPOLINE_LINEAR, trampoline_bytes, trampoline_size) ||
      !daze_kvm_machine_write(machine, RM_TARGET_LINEAR, target, sizeof(target)) ||
      !daze_kvm_machine_write(machine, DAZE_DPMI_RM_GATE_LINEAR, gate, sizeof(gate)))
    return 0;
  memset(regs, 0, sizeof(*regs));
  regs->rax = daze_read_u32(frame + DAZE_DPMI_RM_EAX);
  regs->rbx = daze_read_u32(frame + DAZE_DPMI_RM_EBX);
  regs->rcx = daze_read_u32(frame + DAZE_DPMI_RM_ECX);
  regs->rdx = daze_read_u32(frame + DAZE_DPMI_RM_EDX);
  regs->rsi = daze_read_u32(frame + DAZE_DPMI_RM_ESI);
  regs->rdi = daze_read_u32(frame + DAZE_DPMI_RM_EDI);
  regs->rbp = daze_read_u32(frame + DAZE_DPMI_RM_EBP);
  regs->rip = RM_TRAMPOLINE_IP;
  regs->rsp = rm->procedure_sp;
  /* Software-supplied FLAGS may contain reserved bits that hardware VM entry
   * rejects; preserve the defined 16-bit flags and enforce the fixed bit. */
  regs->rflags = (daze_read_u16(frame + DAZE_DPMI_RM_FLAGS) & 0x7fd5u) | 2u;
  sregs->cs = protected_code_segment(RM_GATE_CS_SELECTOR, RM_GATE_CS_BASE);
  real_segment(&sregs->ss, rm->frame_ss, 0x3);
  real_segment(&sregs->ds, daze_read_u16(frame + DAZE_DPMI_RM_DS), 0x3);
  real_segment(&sregs->es, daze_read_u16(frame + DAZE_DPMI_RM_ES), 0x3);
  real_segment(&sregs->fs, daze_read_u16(frame + DAZE_DPMI_RM_FS), 0x3);
  real_segment(&sregs->gs, daze_read_u16(frame + DAZE_DPMI_RM_GS), 0x3);
  /* CR0.PE changes do not reset the cached IDT; install the base-0 IVT before the first
   * real-mode interrupt. */
  sregs->idt.base = 0;
  sregs->idt.limit = 0x3ff;
  return daze_kvm_machine_set_sregs(machine, sregs) == DAZE_KVM_MACHINE_OK &&
         daze_kvm_machine_set_regs(machine, regs) == DAZE_KVM_MACHINE_OK;
}

static int serve_real_mode_dpmi(DazeKvmMachine *machine, const uint8_t record[24],
                                uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE],
                                const DazeKvmDpmiMediator *mediator) {
  const uint16_t ax = daze_read_u16(record);
  const uint16_t bx = daze_read_u16(record + 2);
  const uint16_t cx = daze_read_u16(record + 4);
  const uint16_t dx = daze_read_u16(record + 6);
  DazeDpmiResult result;
  daze_kvm_runner_gate_reply_init(record, reply);
  switch (ax) {
  case DAZE_DPMI_ALLOC_LINEAR: {
    const uint32_t size = ((uint32_t)bx << 16) | cx;
    const DazeDpmiRequest request = {.function = ax, .size = size};
    daze_dpmi_request_allocate_linear_memory(mediator->linear_memory, &request, &result);
    if (!result.success) {
      fprintf(stderr, "kvm-rm-procedure: real-mode 31h/0501h cannot allocate %08" PRIx32 " bytes\n",
              size);
      daze_write_u16(reply, result.dpmi_error);
      daze_write_u16(reply + 14, 3);
    } else {
      daze_write_u16(reply + 2, (uint16_t)(result.base >> 16));
      daze_write_u16(reply + 4, (uint16_t)result.base);
      daze_write_u16(reply + 8, (uint16_t)(result.handle >> 16));
      daze_write_u16(reply + 10, (uint16_t)result.handle);
      daze_write_u16(reply + 14, 2);
    }
    break;
  }
  case DAZE_DPMI_ALLOC_LDT: {
    DazeDpmiLdtAllocator allocator = {.used = mediator->ldt_used,
                                      .capacity = mediator->ldt_used_count,
                                      .first_index = mediator->ldt_first_index};
    if (allocator.used == NULL || allocator.capacity < mediator->ldt_size / 8) return 0;
    const DazeDpmiRequest request = {.function = ax, .count = cx};
    daze_dpmi_request_allocate_ldt_descriptors(&request, &allocator, &result);
    if (!result.success) {
      fprintf(stderr, "kvm-rm-procedure: real-mode 31h/0000h cannot allocate %u LDT descriptors\n",
              cx);
      daze_write_u16(reply, DAZE_DPMI_ERR_LDT_FULL);
      daze_write_u16(reply + 14, 3);
    } else {
      const uint8_t inert_data[8] = {0, 0, 0, 0, 0, 0x92, 0, 0};
      const uint16_t first = (uint16_t)(result.ax >> 3);
      for (uint16_t offset = 0; offset < cx; ++offset) {
        uint32_t destination;
        if (!daze_kvm_dpmi_mediator_descriptor_address(
              mediator, (uint16_t)((first + offset) << 3 | 4u), &destination))
          return 0;
        memcpy((uint8_t *)machine->guest + destination, inert_data, sizeof(inert_data));
      }
      daze_write_u16(reply, result.ax);
      daze_write_u16(reply + 14, 2);
    }
    break;
  }
  case DAZE_DPMI_SET_LIMIT:
  case DAZE_DPMI_SET_LIMIT_2:
  case DAZE_DPMI_SET_ACCESS: {
    const uint32_t operand = ((uint32_t)cx << 16) | dx;
    uint32_t descriptor_address;
    if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, bx, &descriptor_address)) {
      fprintf(stderr, "kvm-rm-procedure: real-mode 31h/%04x invalid LDT selector %04x\n", ax, bx);
      daze_write_u16(reply, ax == DAZE_DPMI_SET_LIMIT_2 ? DAZE_DPMI_ERR_INVALID_SEGMENT
                                                        : DAZE_DPMI_ERR_INVALID_SELECTOR);
      daze_write_u16(reply + 14, 3);
      break;
    }
    const DazeDpmiRequest request = {
      .function = ax, .selector = bx, .operand = operand, .rights = cx};
    uint8_t *descriptor = (uint8_t *)machine->guest + descriptor_address;
    if (ax == DAZE_DPMI_SET_LIMIT)
      daze_dpmi_request_set_segment_base(&request, descriptor, &result);
    else if (ax == DAZE_DPMI_SET_LIMIT_2)
      daze_dpmi_request_set_segment_limit(&request, descriptor, &result);
    else
      daze_dpmi_request_set_access_rights(&request, descriptor, &result);
    if (!result.success) {
      fprintf(stderr, "kvm-rm-procedure: real-mode 31h/%04x rejected selector %04x\n", ax, bx);
      daze_write_u16(reply, result.ax);
      daze_write_u16(reply + 14, 3);
      break;
    }
    memcpy(descriptor, result.descriptor, 8);
    daze_write_u16(reply + 14, 2);
    break;
  }
  case DAZE_DPMI_ALLOC_LDT_MULTI: {
    DazeDpmiLdtAllocator allocator = {.used = mediator->ldt_used,
                                      .capacity = mediator->ldt_used_count,
                                      .first_index = mediator->ldt_first_index};
    uint32_t source_descriptor;
    if (!daze_kvm_dpmi_mediator_gdt_descriptor_address(mediator, bx, &source_descriptor)) {
      fprintf(stderr, "kvm-rm-procedure: real-mode 31h/000ah cannot alias selector %04x\n", bx);
      daze_write_u16(reply, DAZE_DPMI_ERR_INVALID_SELECTOR);
      daze_write_u16(reply + 14, 3);
      break;
    }
    if (allocator.used == NULL || allocator.capacity < mediator->ldt_size / 8) return 0;
    const DazeDpmiRequest request = {.function = ax, .selector = bx};
    daze_dpmi_request_create_data_alias(&request, (uint8_t *)machine->guest + source_descriptor,
                                        &allocator, &result);
    if (!result.success) {
      fprintf(stderr, "kvm-rm-procedure: real-mode 31h/000ah cannot alias selector %04x\n", bx);
      daze_write_u16(reply, result.ax);
      daze_write_u16(reply + 14, 3);
      break;
    }
    uint32_t alias_descriptor;
    if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, result.ax, &alias_descriptor))
      return 0;
    memcpy((uint8_t *)machine->guest + alias_descriptor, result.descriptor, 8);
    daze_write_u16(reply, result.ax);
    daze_write_u16(reply + 14, 2);
    break;
  }
  default:
    fprintf(stderr, "kvm-rm-procedure: unsupported real-mode DPMI 31h/%04x\n", ax);
    return 0;
  }
  return 1;
}

static int serve_runner(DazeKvmMachine *machine, DazeDosfsFileService *files,
                        DazeDosProcessState *process_state, const DazeKvmDpmiMediator *mediator,
                        uint16_t dpmi_entry_segment, uint8_t vector) {
  DazeKvmRunnerGateFrame frame;
  uint8_t record[24] = {0};
  uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE] = {0};
  if (daze_kvm_runner_gate_frame_capture(machine, vector, &frame) != DAZE_KVM_RUNNER_GATE_RESUME_OK)
    return 0;
  daze_write_u16(record, frame.ax);
  daze_write_u16(record + 2, frame.bx);
  daze_write_u16(record + 4, frame.cx);
  daze_write_u16(record + 6, frame.dx);
  daze_write_u16(record + 8, frame.ds);
  daze_write_u16(record + 10, frame.es);
  daze_write_u16(record + 12, frame.si);
  daze_write_u16(record + 14, frame.di);
  daze_write_u16(record + 16, frame.vector);
  daze_write_u16(record + 18, frame.return_ip);
  daze_write_u16(record + 20, frame.return_cs);
  daze_write_u16(record + 22, frame.flags);
  if (vector == 0x31) {
    if (!serve_real_mode_dpmi(machine, record, reply, mediator)) return 0;
    return daze_kvm_runner_gate_frame_reply(machine, &frame, reply) ==
           DAZE_KVM_RUNNER_GATE_RESUME_OK;
  }
  DazeKvmPreflightBoundaryResult broker_result;
  const DazeKvmPreflightBoundaryDisposition status =
    daze_kvm_preflight_boundary_broker(machine, files, process_state, mediator->dos_memory,
                                       dpmi_entry_segment, record, reply, &broker_result);
  if (status != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED) {
    fprintf(stderr,
            "kvm-rm-procedure: runner unsupported ax=%04x bx=%04x cx=%04x dx=%04x ds=%04x "
            "es=%04x si=%04x di=%04x\n",
            daze_read_u16(record), daze_read_u16(record + 2), daze_read_u16(record + 4),
            daze_read_u16(record + 6), daze_read_u16(record + 8), daze_read_u16(record + 10),
            daze_read_u16(record + 12), daze_read_u16(record + 14));
    return 0;
  }
  return daze_kvm_runner_gate_frame_reply(machine, &frame, reply) == DAZE_KVM_RUNNER_GATE_RESUME_OK;
}

static void record_reflect_runner(DazeRunMetrics *metrics, uint8_t vector, uint64_t nanoseconds) {
  if (metrics == NULL || !metrics->enabled) return;
  metrics->kvm_rm_procedure_reflect_runner_calls++;
  metrics->kvm_rm_procedure_reflect_runner_nanoseconds += nanoseconds;
  for (size_t index = 0; index < metrics->kvm_rm_procedure_reflect_vector_count; ++index) {
    DazeRunMetricsRmReflectVector *entry = &metrics->kvm_rm_procedure_reflect_vectors[index];
    if (entry->vector == vector) {
      entry->calls++;
      entry->nanoseconds += nanoseconds;
      return;
    }
  }
  if (metrics->kvm_rm_procedure_reflect_vector_count ==
      DAZE_RUN_METRICS_RM_REFLECT_VECTOR_CAPACITY) {
    metrics->kvm_rm_procedure_reflect_vector_overflow_calls++;
    return;
  }
  metrics->kvm_rm_procedure_reflect_vectors[metrics->kvm_rm_procedure_reflect_vector_count++] =
    (DazeRunMetricsRmReflectVector){.vector = vector, .calls = 1, .nanoseconds = nanoseconds};
}

static int timed_serve_runner(DazeKvmMachine *machine, DazeDosfsFileService *files,
                              DazeDosProcessState *process_state,
                              const DazeKvmDpmiMediator *mediator, uint16_t dpmi_entry_segment,
                              uint8_t vector) {
  DazeRunMetrics *const metrics = machine->run_metrics;
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const int status =
    serve_runner(machine, files, process_state, mediator, dpmi_entry_segment, vector);
  if (metrics != NULL && metrics->enabled)
    record_reflect_runner(metrics, vector, elapsed_nanoseconds(started, monotonic_nanoseconds()));
  return status;
}

static int write_back_frame(DazeKvmMachine *machine, uint32_t frame_address,
                            struct kvm_sregs *returned) {
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (daze_kvm_machine_get_regs(machine, &regs) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_get_sregs(machine, &sregs) != DAZE_KVM_MACHINE_OK)
    return 0;
  uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE];
  memcpy(frame, (const uint8_t *)machine->guest + frame_address, sizeof(frame));
  const DazeDpmiRmWriteBack image = {
    .edi = (uint32_t)regs.rdi,
    .esi = (uint32_t)regs.rsi,
    .ebp = (uint32_t)regs.rbp,
    .ebx = (uint32_t)regs.rbx,
    .edx = (uint32_t)regs.rdx,
    .ecx = (uint32_t)regs.rcx,
    .eax = (uint32_t)regs.rax,
    .flags = (uint16_t)regs.rflags,
    .es = sregs.es.selector,
    .ds = sregs.ds.selector,
    .fs = sregs.fs.selector,
    .gs = sregs.gs.selector,
  };
  daze_dpmi_rm_frame_write_back(frame, &image);
  memcpy((uint8_t *)machine->guest + frame_address, frame, sizeof(frame));
  *returned = sregs;
  return 1;
}

enum { RMRUN_STOP, RMRUN_COMPLETE, RMRUN_BRIDGED };

static int returned_to_gate(const struct kvm_regs *regs, const struct kvm_sregs *sregs) {
  /* VMX and SVM retire HLT before KVM_EXIT_HLT; Daze has no in-kernel LAPIC. */
  return !(sregs->cr0 & 1) && sregs->cs.selector == DAZE_DPMI_RM_RETURN_CS &&
         sregs->cs.base == DAZE_DPMI_RM_GATE_LINEAR && regs->rip == DAZE_DPMI_RM_RETURN_IP + 1;
}

static int reflect_run(DazeKvmMachine *machine, DazeDosfsFileService *files,
                       DazeDosProcessState *process_state, const DazeKvmDpmiMediator *mediator,
                       uint16_t dpmi_entry_segment, int bridge, DazeKvmDpmiEntryResult *successor,
                       int observed_first) {
  const struct kvm_run *run = (const struct kvm_run *)machine->run;
  uint32_t callback = daze_kvm_rm_entry_count(machine);
  for (size_t step = 0; step < RM_MAX_STEPS; ++step) {
    if (!observed_first && timed_rm_kvm_run(machine) < 0) {
      fprintf(stderr, "kvm-rm-procedure: run failed\n");
      return RMRUN_STOP;
    }
    observed_first = 0;
    if (!daze_kvm_write_batch_drain(machine, files)) return RMRUN_STOP;
    const uint32_t next_callback = daze_kvm_rm_entry_count(machine);
    if (next_callback != callback) {
      callback = next_callback;
      step = 0;
    }
    if (bridge &&
        daze_read_u16((const uint8_t *)machine->guest + k_dpmi_rm_return_bridge + 0x642) == 1) {
      /* The owner loop classifies this actual protected exit, including faults. */
      return daze_kvm_dpmi_entry_observe_mediator_or_capture(machine, successor) ==
                 DAZE_KVM_DPMI_ENTRY_OK
               ? RMRUN_BRIDGED
               : RMRUN_STOP;
    }
    if (run->exit_reason == KVM_EXIT_HLT) {
      struct kvm_regs regs = {0};
      struct kvm_sregs sregs = {0};
      if (daze_kvm_machine_get_regs(machine, &regs) == DAZE_KVM_MACHINE_OK &&
          daze_kvm_machine_get_sregs(machine, &sregs) == DAZE_KVM_MACHINE_OK &&
          returned_to_gate(&regs, &sregs))
        return RMRUN_COMPLETE;
      fprintf(stderr, "kvm-rm-procedure: unexpected halt cr0=%llx cs=%04x base=%llx rip=%llx\n",
              (unsigned long long)sregs.cr0, sregs.cs.selector, (unsigned long long)sregs.cs.base,
              (unsigned long long)regs.rip);
    }
    if (run->exit_reason != KVM_EXIT_IO) {
      struct kvm_regs uregs = {0};
      const int have_regs = ioctl(machine->vcpu, KVM_GET_REGS, &uregs) == 0;
      const uint16_t ivt0 = daze_read_u16((const uint8_t *)machine->guest + 18);
      const uint16_t ivt2 = daze_read_u16((const uint8_t *)machine->guest + 20);
      const uint16_t ivt31_0 = daze_read_u16((const uint8_t *)machine->guest + 0x31 * 4);
      const uint16_t ivt31_2 = daze_read_u16((const uint8_t *)machine->guest + 0x31 * 4 + 2);
      fprintf(stderr,
              "kvm-rm-procedure: unexpected exit reason %u ip=%llx ivt6=%04x:%04x "
              "ivt31=%04x:%04x sp=%llx\n",
              run->exit_reason, (unsigned long long)uregs.rip, ivt2, ivt0, ivt31_2, ivt31_0,
              (unsigned long long)uregs.rsp);
      if (run->exit_reason == KVM_EXIT_FAIL_ENTRY)
        fprintf(stderr, "kvm-rm-procedure: hardware entry failure reason=%016llx\n",
                (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
      if (getenv("DAZE_KVM_RM_CRASH_DUMP") != NULL) {
        if (have_regs)
          dump_rejected_far_load(machine, &uregs);
        else
          fprintf(stderr, "kvm-rm-procedure:   registers unavailable\n");
      }
      return RMRUN_STOP;
    }
    const uint8_t direction = run->io.direction;
    const uint16_t port = run->io.port;
    const uint8_t size = run->io.size;
    const uint32_t count = run->io.count;
    const uint64_t data_offset = run->io.data_offset;
    if (size != 1 || count != 1 || data_offset > machine->run_size ||
        size > machine->run_size - data_offset) {
      fprintf(stderr, "kvm-rm-procedure: unexpected port access shape\n");
      return RMRUN_STOP;
    }
    uint8_t *value = (uint8_t *)run + data_offset;
    if (direction == KVM_EXIT_IO_OUT) {
      if (port == RM_CONTINUE_PORT) continue;
      if (port == RM_GATE_PORT) {
        if (*value == 0x10 || *value == 0x11 || *value == 0x1a || *value == 0x21 ||
            *value == 0x2f || *value == 0x31 || *value == 0xfe) {
          if (!timed_serve_runner(machine, files, process_state, mediator, dpmi_entry_segment,
                                  *value)) {
            fprintf(stderr, "kvm-rm-procedure: runner boundary not served\n");
            return RMRUN_STOP;
          }
          if (bridge && *value == 0x31) {
            daze_kvm_rm_entry_invalidate(machine);
            /* A real-mode DPMI call may change descriptors used by the parked caches. */
            const uint8_t halt = 0xf4; /* hlt */
            if (!daze_kvm_machine_write(machine, DAZE_DPMI_RM_GATE_LINEAR, &halt, 1))
              return RMRUN_STOP;
            bridge = 0;
          }
          continue;
        }
        fprintf(stderr, "kvm-rm-procedure: unexpected gate marker %02x\n", *value);
        return RMRUN_STOP;
      }
      fprintf(stderr, "kvm-rm-procedure: unexpected port out %04x\n", port);
      return RMRUN_STOP;
    }
    if (port == RM_PIC_PORT_1 || port == RM_PIC_PORT_2) {
      *value = 0;
      continue;
    }
    fprintf(stderr, "kvm-rm-procedure: unexpected port in %04x\n", port);
    return RMRUN_STOP;
  }
  fprintf(stderr, "kvm-rm-procedure: step limit reached\n");
  return RMRUN_STOP;
}
static void dump_rejected_far_load(DazeKvmMachine *machine, const struct kvm_regs *uregs) {
  struct kvm_sregs sregs_array;
  fprintf(stderr,
          "kvm-rm-procedure:   gprs rax=%llx rbx=%llx rcx=%llx rdx=%llx "
          "rsi=%llx rdi=%llx rbp=%llx rsp=%llx rflags=%llx\n",
          (unsigned long long)uregs->rax, (unsigned long long)uregs->rbx,
          (unsigned long long)uregs->rcx, (unsigned long long)uregs->rdx,
          (unsigned long long)uregs->rsi, (unsigned long long)uregs->rdi,
          (unsigned long long)uregs->rbp, (unsigned long long)uregs->rsp,
          (unsigned long long)uregs->rflags);
  if (ioctl(machine->vcpu, KVM_GET_SREGS, &sregs_array) != 0) {
    fprintf(stderr, "kvm-rm-procedure:   segments unavailable\n");
    return;
  }
  fprintf(stderr,
          "kvm-rm-procedure:   sregs cr0=%016llx cr2=%016llx cr3=%016llx cr4=%016llx "
          "cr8=%016llx efer=%016llx eip=%08llx\n",
          (unsigned long long)sregs_array.cr0, (unsigned long long)sregs_array.cr2,
          (unsigned long long)sregs_array.cr3, (unsigned long long)sregs_array.cr4,
          (unsigned long long)sregs_array.cr8, (unsigned long long)sregs_array.efer,
          (unsigned long long)uregs->rip);
  fprintf(stderr,
          "kvm-rm-procedure:   gdtr base=%016llx limit=%04x ldtr=%04x tr=%04x "
          "idt base=%016llx limit=%04x\n",
          (unsigned long long)sregs_array.gdt.base, sregs_array.gdt.limit, sregs_array.ldt.selector,
          sregs_array.tr.selector, (unsigned long long)sregs_array.idt.base, sregs_array.idt.limit);
  const struct kvm_segment *segs[6] = {&sregs_array.cs, &sregs_array.ss, &sregs_array.ds,
                                       &sregs_array.es, &sregs_array.fs, &sregs_array.gs};
  const char *names[6] = {"cs", "ss", "ds", "es", "fs", "gs"};
  for (int index = 0; index < 6; ++index) {
    const struct kvm_segment *segment = segs[index];
    fprintf(stderr,
            "kvm-rm-procedure:   %s sel=%04x base=%016llx limit=%08x type=%02x s=%u dpl=%u p=%u "
            "db=%u g=%u avl=%u l=%u unusable=%u\n",
            names[index], segment->selector, (unsigned long long)segment->base, segment->limit,
            segment->type, segment->s, segment->dpl, segment->present, segment->db, segment->g,
            segment->avl, segment->l, segment->unusable);
  }
  const uint64_t linear = sregs_array.cs.base + uregs->rip;
  const uint64_t context = linear >= 48 ? linear - 48 : 0;
  fprintf(stderr, "kvm-rm-procedure:   cs:ip %04x:%08llx context@%llx bytes",
          sregs_array.cs.selector, (unsigned long long)uregs->rip, (unsigned long long)context);
  if (linear >= sregs_array.cs.base && context <= UINT32_MAX &&
      daze_kvm_range_fits(machine->guest_size, (uint32_t)context, 64)) {
    const uint8_t *bytes = (const uint8_t *)machine->guest + context;
    for (size_t offset = 0; offset < 64; ++offset)
      fprintf(stderr, " %02x", bytes[offset]);
  } else {
    fprintf(stderr, " unavailable");
  }
  fprintf(stderr, "\n");
}

static int native_parked(DazeKvmMachine *machine, ParkedState *parked) {
  if (!daze_kvm_range_fits(machine->guest_size, DAZE_KVM_RM_ENTRY_CONTROL,
                           DAZE_KVM_RM_ENTRY_CONTROL_SIZE))
    return 0;
  const uint8_t *guest = machine->guest;
  memcpy(&parked->sregs, guest + DAZE_KVM_RM_ENTRY_CONTROL + 0x100, sizeof(parked->sregs));
  if (daze_kvm_machine_get_regs(machine, &parked->regs) != DAZE_KVM_MACHINE_OK) return 0;
  const uint8_t *p = guest + DAZE_KVM_RM_ENTRY_PARKED;
  parked->regs.rax = daze_read_u32(p);
  parked->regs.rbx = daze_read_u32(p + 4);
  parked->regs.rcx = daze_read_u32(p + 8);
  parked->regs.rdx = daze_read_u32(p + 12);
  parked->regs.rsi = daze_read_u32(p + 16);
  parked->regs.rdi = daze_read_u32(p + 20);
  parked->regs.rbp = daze_read_u32(p + 24);
  parked->regs.rsp = daze_read_u32(p + 28);
  parked->regs.rflags = daze_read_u32(p + 32);
  parked->regs.rip = daze_read_u32(p + 0x3c);
  parked->sregs.cr0 = daze_read_u32(p + 0x24);
  return 1;
}

static int native_host_return(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *successor) {
  ParkedState parked;
  struct kvm_sregs returned;
  const uint32_t frame =
    daze_read_u32((const uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_PARKED + 0x28);
  if (!native_parked(machine, &parked) ||
      !daze_kvm_range_fits(machine->guest_size, frame, DAZE_DPMI_RM_FRAME_SIZE) ||
      !write_back_frame(machine, frame, &returned) ||
      prepare_protected_return(machine, &parked, &returned) < 0 ||
      daze_kvm_machine_set_sregs(machine, &parked.sregs) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_set_regs(machine, &parked.regs) != DAZE_KVM_MACHINE_OK)
    return 0;
  daze_write_u32(
    (uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL + DAZE_KVM_RM_ENTRY_ACTIVE_OFFSET, 0);
  return daze_kvm_dpmi_entry_continue_mediator_or_capture(machine, successor) ==
         DAZE_KVM_DPMI_ENTRY_OK;
}
#endif

int daze_kvm_rm_entry_continue(const DazeKvmRmProcedureInput *input,
                               DazeKvmDpmiEntryResult *successor) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  if (input == NULL || successor == NULL || input->mediator == NULL || input->files == NULL ||
      input->process_state == NULL || !daze_kvm_rm_entry_active(input->machine) ||
      input->machine->run == NULL || input->machine->vcpu < 0)
    return 0;
  const int status = reflect_run(input->machine, input->files, input->process_state,
                                 input->mediator, input->dpmi_entry_segment, 1, successor, 1);
  if (status == RMRUN_BRIDGED) return 1;
  return status == RMRUN_COMPLETE && native_host_return(input->machine, successor);
#else
  (void)input;
  (void)successor;
  return 0;
#endif
}

int daze_kvm_rm_procedure_reflect(const DazeKvmRmProcedureInput *input,
                                  DazeKvmDpmiEntryResult *successor) {
  if (successor != NULL) *successor = (DazeKvmDpmiEntryResult){0};
  if (input == NULL || successor == NULL || input->machine == NULL || input->mediator == NULL ||
      input->files == NULL || input->mediator->guest != input->machine->guest ||
      input->mediator->guest_size != input->machine->guest_size ||
      !input->mediator->rm_procedure_present)
    return 0;
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  DazeKvmMachine *const machine = input->machine;
  DazeRunMetrics *const metrics = machine->run_metrics;
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const DazeDpmiRmProcedure *const rm = &input->mediator->rm_procedure;
  if (daze_kvm_rm_entry_installed(machine) &&
      (daze_guest_ranges_overlap(rm->frame_address, DAZE_DPMI_RM_FRAME_SIZE, k_dpmi_rm_entry_linear,
                                 k_dpmi_rm_entry_size) ||
       daze_guest_ranges_overlap(rm->stack_address, 4 + rm->parameter_bytes, k_dpmi_rm_entry_linear,
                                 k_dpmi_rm_entry_size))) {
    fprintf(stderr, "kvm-rm-procedure: frame or stack overlaps private callback entry\n");
    return 0;
  }
  uint64_t runner_calls_before = 0, date_calls_before = 0, time_calls_before = 0;
  uint64_t reflect_run_before = 0, service_before = 0;
  if (metrics != NULL && metrics->enabled) {
    runner_calls_before = metrics->kvm_rm_procedure_reflect_runner_calls;
    date_calls_before = metrics->kvm_dos_functions[0x2a];
    time_calls_before = metrics->kvm_dos_functions[0x2c];
    reflect_run_before = metrics->kvm_rm_procedure_run_nanoseconds;
    service_before = metrics->kvm_boundary_broker_nanoseconds;
  }
  if (machine->vcpu < 0 || machine->run == NULL ||
      !daze_kvm_range_fits(machine->guest_size, rm->frame_address, DAZE_DPMI_RM_FRAME_SIZE) ||
      !daze_kvm_range_fits(machine->guest_size, rm->stack_address,
                           input->mediator->rm_procedure_is_interrupt ? 6
                                                                      : 4 + rm->parameter_bytes))
    return 0;
  ParkedState parked;
  const uint64_t parked_capture_started =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  if (daze_kvm_machine_get_regs(machine, &parked.regs) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_get_sregs(machine, &parked.sregs) != DAZE_KVM_MACHINE_OK) {
    fprintf(stderr, "kvm-rm-procedure: cannot capture parked gate\n");
    return 0;
  }
  const uint64_t parked_capture_finished =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  if (rm->parameter_bytes != 0) {
    /* The protected mediator's EBP points at its 12-byte CPU INT frame.
     * DPMI copies words from the client's stack above that frame. */
    uint64_t offset = parked.regs.rbp + 12;
    uint64_t source = parked.sregs.ss.base + offset;
    if (offset + rm->parameter_bytes - 1 > parked.sregs.ss.limit || source > UINT32_MAX ||
        !daze_kvm_range_fits(machine->guest_size, (uint32_t)source, rm->parameter_bytes))
      return 0;
    memcpy((uint8_t *)machine->guest + rm->stack_address + 4,
           (const uint8_t *)machine->guest + source, rm->parameter_bytes);
  }
  /* Retire deferred OUT before the detour, or restoration would replay it. */
  DazeKvmDpmiEntryResult retired;
  const uint64_t retire_started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const int retired_status = daze_kvm_dpmi_entry_retire_mediator_out_observe(
    machine, (uint32_t)parked.sregs.cs.base, (uint32_t)parked.regs.rip, &retired);
  const uint64_t retire_finished =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  if (retired_status == DAZE_KVM_DPMI_ENTRY_INVALID) {
    fprintf(stderr, "kvm-rm-procedure: parked state is not the mediator OUT (cs=%04x rip=%08x)\n",
            parked.sregs.cs.selector, (unsigned)parked.regs.rip);
    return 0;
  }
  if (retired_status != DAZE_KVM_DPMI_ENTRY_OK) {
    const DazeKvmDpmiEntryObservation *obs = &retired.observation;
    fprintf(stderr,
            "kvm-rm-procedure: mediator OUT did not retire to its successor (kind=%d raw=%u "
            "cs:ip=%04x:%08x) -- terminal boundary, failing KVM attempt\n",
            obs->kind, obs->raw_exit_reason, retired.cs, (unsigned)retired.rip);
    return 0;
  }
  const uint64_t post_pio_capture_started =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  /* The protected return belongs immediately after the validated OUT. */
  ParkedState post_pio = parked;
  post_pio.regs.rip += 2;
  const uint64_t post_pio_capture_finished =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE];
  memcpy(frame, (const uint8_t *)machine->guest + rm->frame_address, sizeof(frame));
  if (input->mediator->rm_procedure_is_interrupt) {
    const uint16_t iret_return[] = {DAZE_DPMI_RM_RETURN_IP, DAZE_DPMI_RM_RETURN_CS,
                                    daze_read_u16(frame + DAZE_DPMI_RM_FLAGS)};
    memcpy((uint8_t *)machine->guest + rm->stack_address, iret_return, sizeof(iret_return));
  } else {
    uint8_t far_return[4];
    if (!daze_dpmi_rm_far_return(far_return)) return 0;
    memcpy((uint8_t *)machine->guest + rm->stack_address, far_return, sizeof(far_return));
  }
  struct kvm_regs regs;
  struct kvm_sregs sregs = parked.sregs;
  const uint64_t transition_started =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  if (!enter_guest_transition(machine, frame, rm, input->mediator->rm_procedure_is_interrupt, &regs,
                              &sregs)) {
    fprintf(stderr, "kvm-rm-procedure: cannot enter guest trampoline\n");
    return 0;
  }
  const int bridge =
    input->protected_return_linear == 0 &&
        !daze_guest_ranges_overlap(rm->stack_address, 6 + rm->parameter_bytes,
                                   k_dpmi_rm_return_bridge, k_dpmi_rm_return_bridge_size)
      ? install_return_bridge(machine, &post_pio, rm->frame_address)
      : 0;
  if (bridge < 0) return 0;
  if (daze_kvm_rm_entry_installed(machine)) {
    daze_kvm_rm_entry_invalidate(machine);
    daze_write_u32(
      (uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL + DAZE_KVM_RM_ENTRY_ACTIVE_OFFSET, 0);
    if (bridge == 1 && input->protected_return_linear == 0)
      native_arm(machine, &post_pio, rm->frame_address);
  }
  const uint64_t transition_finished =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const uint64_t reflect_started =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const int status = reflect_run(machine, input->files, input->process_state, input->mediator,
                                 input->dpmi_entry_segment, bridge, successor, 0);
  const uint64_t reflect_finished =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const uint64_t resume_run_before =
    metrics != NULL && metrics->enabled
      ? metrics->kvm_dpmi_run_nanoseconds[DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_ONCE]
      : 0;
  const uint64_t resume_capture_before =
    metrics != NULL && metrics->enabled
      ? metrics->kvm_dpmi_state_capture_nanoseconds[DAZE_RUN_METRICS_DPMI_CAPTURE_CONTINUE_ONCE]
      : 0;
  uint64_t resume_started = reflect_finished;
  int resumed = status == RMRUN_BRIDGED;
  if (status == RMRUN_COMPLETE && daze_kvm_rm_entry_active(machine)) {
    resumed = native_host_return(machine, successor);
  } else if (!resumed) {
    int completed = 0;
    struct kvm_sregs returned;
    if (status == RMRUN_COMPLETE)
      completed = write_back_frame(machine, rm->frame_address, &returned);
    if (completed) {
      if (prepare_protected_return(machine, &post_pio, &returned) < 0) {
        fprintf(stderr, "kvm-rm-procedure: cannot prepare protected return\n");
        return 0;
      }
    }
    /* Restore the immediate successor, before any mailbox load has executed. */
    if (daze_kvm_machine_set_sregs(machine, &post_pio.sregs) != DAZE_KVM_MACHINE_OK ||
        daze_kvm_machine_set_regs(machine, &post_pio.regs) != DAZE_KVM_MACHINE_OK)
      return 0;
    if (!completed) return 0;
    resume_started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
    if (input->protected_return_linear != 0) {
      struct kvm_guest_debug debug = {.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP};
      debug.arch.debugreg[0] = input->protected_return_linear;
      debug.arch.debugreg[7] = 3;
      if (daze_kvm_machine_set_guest_debug(machine, &debug) < 0) return 0;
    }
    resumed = daze_kvm_dpmi_entry_continue_mediator_or_capture(machine, successor) ==
              DAZE_KVM_DPMI_ENTRY_OK;
  }
  const uint64_t resume_finished =
    metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  if (metrics != NULL && metrics->enabled) {
    const uint64_t finished = monotonic_nanoseconds();
    metrics->kvm_rm_procedure_calls++;
    if (status == RMRUN_BRIDGED) metrics->kvm_rm_procedure_bridged_calls++;
    metrics->kvm_rm_procedure_nanoseconds += elapsed_nanoseconds(started, finished);
    metrics->kvm_rm_procedure_setup_nanoseconds += elapsed_nanoseconds(started, reflect_started);
    metrics->kvm_rm_procedure_setup_parked_capture_nanoseconds +=
      elapsed_nanoseconds(parked_capture_started, parked_capture_finished);
    metrics->kvm_rm_procedure_setup_retire_nanoseconds +=
      elapsed_nanoseconds(retire_started, retire_finished);
    metrics->kvm_rm_procedure_setup_post_pio_capture_nanoseconds +=
      elapsed_nanoseconds(post_pio_capture_started, post_pio_capture_finished);
    metrics->kvm_rm_procedure_setup_transition_nanoseconds +=
      elapsed_nanoseconds(transition_started, transition_finished);
    metrics->kvm_rm_procedure_reflect_nanoseconds +=
      elapsed_nanoseconds(reflect_started, reflect_finished);
    metrics->kvm_rm_procedure_cleanup_nanoseconds +=
      elapsed_nanoseconds(reflect_finished, resume_started);
    metrics->kvm_rm_procedure_resume_nanoseconds +=
      elapsed_nanoseconds(resume_started, resume_finished);
    metrics->kvm_rm_procedure_resume_run_nanoseconds +=
      metrics->kvm_dpmi_run_nanoseconds[DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_ONCE] -
      resume_run_before;
    metrics->kvm_rm_procedure_resume_capture_nanoseconds +=
      metrics->kvm_dpmi_state_capture_nanoseconds[DAZE_RUN_METRICS_DPMI_CAPTURE_CONTINUE_ONCE] -
      resume_capture_before;
    record_procedure_cost(
      metrics, metrics->kvm_rm_procedure_reflect_runner_calls - runner_calls_before,
      metrics->kvm_dos_functions[0x2a] - date_calls_before,
      metrics->kvm_dos_functions[0x2c] - time_calls_before,
      &(const DazeRunMetricsRmProcedureCost){
        .total_nanoseconds = elapsed_nanoseconds(started, finished),
        .setup_nanoseconds = elapsed_nanoseconds(started, reflect_started),
        .reflect_nanoseconds = elapsed_nanoseconds(reflect_started, reflect_finished),
        .cleanup_nanoseconds = elapsed_nanoseconds(reflect_finished, resume_started),
        .resume_nanoseconds = elapsed_nanoseconds(resume_started, resume_finished),
        .reflect_run_nanoseconds = metrics->kvm_rm_procedure_run_nanoseconds - reflect_run_before,
        .resume_run_nanoseconds =
          metrics->kvm_dpmi_run_nanoseconds[DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_ONCE] -
          resume_run_before,
        .service_nanoseconds = metrics->kvm_boundary_broker_nanoseconds - service_before});
  }
  return resumed;
#else
  (void)input;
  return 0;
#endif
}
