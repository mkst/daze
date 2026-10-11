#include "entry.h"

#include "machine_access.h"

#include "dpmi_function.h"
#include "kvm_bytes.h"
#include "mediator.h"
#include "kvm_range.h"
#include "monotonic_clock.h"
#include "port.h"
#include "protected.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static int fail_entry_trace_armed(void) {
  const char *const trace = getenv("DAZE_KVM_FAIL_ENTRY_TRACE");
  return trace != NULL && trace[0] == '1' && trace[1] == '\0';
}

int daze_kvm_dpmi_entry_fail_entry_trace_enabled(void) {
  return fail_entry_trace_armed();
}

const char *daze_kvm_dpmi_entry_fail_entry_trace_exit_name(uint32_t raw_exit_reason) {
  switch (raw_exit_reason) {
  case 0:
    return "KVM_EXIT_UNKNOWN";
  case 1:
    return "KVM_EXIT_EXCEPTION";
  case 2:
    return "KVM_EXIT_IO";
  case 3:
    return "KVM_EXIT_HYPERCALL";
  case 4:
    return "KVM_EXIT_DEBUG";
  case 5:
    return "KVM_EXIT_HLT";
  case 6:
    return "KVM_EXIT_MMIO";
  case 7:
    return "KVM_EXIT_IRQ_WINDOW_OPEN";
  case 8:
    return "KVM_EXIT_SHUTDOWN";
  case 9:
    return "KVM_EXIT_FAIL_ENTRY";
  case 10:
    return "KVM_EXIT_INTR";
  case 11:
    return "KVM_EXIT_SET_TPR";
  case 12:
    return "KVM_EXIT_TPR_ACCESS";
  case 13:
    return "KVM_EXIT_S390_SIEIC";
  case 14:
    return "KVM_EXIT_S390_RESET";
  case 15:
    return "KVM_EXIT_DCR";
  case 16:
    return "KVM_EXIT_NMI";
  case 17:
    return "KVM_EXIT_INTERNAL_ERROR";
  case 18:
    return "KVM_EXIT_OSI";
  case 19:
    return "KVM_EXIT_PAPR_HCALL";
  case 20:
    return "KVM_EXIT_S390_UCONTROL";
  case 21:
    return "KVM_EXIT_WATCHDOG";
  case 22:
    return "KVM_EXIT_S390_TSCH";
  case 23:
    return "KVM_EXIT_EPR";
  case 24:
    return "KVM_EXIT_SYSTEM_EVENT";
  case 25:
    return "KVM_EXIT_S390_STSI";
  default:
    return "KVM_EXIT_?";
  }
}

void daze_kvm_dpmi_entry_fail_entry_trace_capture(DazeKvmFailEntryTrace *trace,
                                                  const uint8_t *guest, size_t guest_size) {
  if (trace == NULL) return;
  trace->stack_word_count = 0;
  trace->stack_linear_valid = 0;
  trace->exception_gate_valid = 0;
  trace->handler_code_valid = 0;
  trace->handler_code_count = 0;
  if (guest == NULL) return;
  const uint32_t exception_gate_offset =
    (uint32_t)DAZE_KVM_FAIL_ENTRY_TRACE_EXCEPTION_VECTOR * DAZE_KVM_FAIL_ENTRY_TRACE_IDT_GATE_BYTES;
  if (trace->idt_limit >= exception_gate_offset + DAZE_KVM_FAIL_ENTRY_TRACE_IDT_GATE_BYTES - 1u &&
      trace->idt_base <= UINT32_MAX - exception_gate_offset) {
    const uint32_t exception_gate = trace->idt_base + exception_gate_offset;
    if (daze_kvm_range_fits(guest_size, exception_gate, sizeof(trace->exception_gate))) {
      memcpy(trace->exception_gate, guest + exception_gate, sizeof(trace->exception_gate));
      trace->exception_gate_valid = 1;
    }
  }
  const uint32_t stack = trace->ss.base + (uint32_t)trace->rsp;
  if (stack < trace->ss.base) return;
  trace->stack_linear = stack;
  trace->stack_linear_valid = 1;
  for (uint32_t index = 0; index < DAZE_KVM_FAIL_ENTRY_TRACE_WORDS; ++index) {
    const uint32_t offset = stack + index * 2;
    if (!daze_kvm_range_fits(guest_size, offset, 2)) break;
    trace->stack_words[index] = daze_read_u16(guest + offset);
    trace->stack_word_count++;
  }
  trace->instruction_count = 0;
  trace->handler_descriptor_valid = 0;
  const uint32_t instruction = trace->cs.base + (uint32_t)trace->rip;
  const uint32_t context_start = instruction >= 0x40u ? instruction - 0x40u : 0u;
  for (uint32_t index = 0; index < sizeof(trace->instruction_bytes); ++index) {
    if (!daze_kvm_range_fits(guest_size, instruction + index, 1)) break;
    trace->instruction_bytes[index] = guest[instruction + index];
    trace->instruction_count++;
  }
  for (uint32_t index = 0; index < 0x40u; ++index) {
    if (!daze_kvm_range_fits(guest_size, context_start + index, 1)) break;
    trace->context_bytes[index] = guest[context_start + index];
    trace->context_count++;
  }
  const uint32_t handler = trace->gdt_base + 8u * DAZE_KVM_FAIL_ENTRY_TRACE_HANDLER_INDEX;
  if (daze_kvm_range_fits(guest_size, handler, sizeof(trace->handler_descriptor))) {
    memcpy(trace->handler_descriptor, guest + handler, sizeof(trace->handler_descriptor));
    trace->handler_descriptor_valid = 1;
    const uint32_t handler_linear =
      ((uint32_t)trace->handler_descriptor[2] | ((uint32_t)trace->handler_descriptor[3] << 8) |
       ((uint32_t)trace->handler_descriptor[4] << 16) |
       ((uint32_t)trace->handler_descriptor[7] << 24)) +
      ((uint32_t)trace->exception_gate[0] | ((uint32_t)trace->exception_gate[1] << 8));
    for (uint32_t index = 0; index < sizeof(trace->handler_code); ++index) {
      if (!daze_kvm_range_fits(guest_size, handler_linear + index, 1)) break;
      trace->handler_code[index] = guest[handler_linear + index];
      trace->handler_code_count++;
    }
    trace->handler_code_valid = 1;
  }
  trace->code_descriptor_valid = 0;
  trace->target_descriptor_valid = 0;
  const uint32_t ldt = trace->ldt.base;
  if (daze_kvm_range_fits(guest_size, ldt + 8u * DAZE_KVM_FAIL_ENTRY_TRACE_CODE_INDEX,
                          sizeof(trace->code_descriptor))) {
    memcpy(trace->code_descriptor, guest + ldt + 8u * DAZE_KVM_FAIL_ENTRY_TRACE_CODE_INDEX,
           sizeof(trace->code_descriptor));
    trace->code_descriptor_valid = 1;
  }
  if (daze_kvm_range_fits(guest_size, ldt + 8u * DAZE_KVM_FAIL_ENTRY_TRACE_TARGET_INDEX,
                          sizeof(trace->target_descriptor))) {
    memcpy(trace->target_descriptor, guest + ldt + 8u * DAZE_KVM_FAIL_ENTRY_TRACE_TARGET_INDEX,
           sizeof(trace->target_descriptor));
    trace->target_descriptor_valid = 1;
  }
}

static void fail_entry_trace_segment(FILE *out, const char *label,
                                     const DazeKvmFailEntryTraceSegment *segment) {
  fprintf(out, " %s=%04x:%08x/%08x/type%02x/p%u/db%u", label, segment->selector, segment->base,
          segment->limit, segment->type & 0x1fu, (unsigned)((segment->type & 0x80u) != 0),
          (unsigned)(segment->db & 1u));
}

void daze_kvm_dpmi_entry_fail_entry_trace_report(const DazeKvmFailEntryTrace *trace) {
  if (trace == NULL) return;
  fprintf(stderr, "kvmd: terminal-entry exit=%u/%s fail-entry-reason=", trace->raw_exit_reason,
          daze_kvm_dpmi_entry_fail_entry_trace_exit_name(trace->raw_exit_reason));
  if (trace->hardware_entry_failure_reason_present)
    fprintf(stderr, "%016llx", (unsigned long long)trace->hardware_entry_failure_reason);
  else
    fputs("absent", stderr);
  fputc('\n', stderr);
  fprintf(stderr,
          "kvmd: terminal-entry cr0=%016llx cr4=%016llx efer=%016llx rflags=%016llx "
          "rip=%016llx rsp=%016llx\n",
          (unsigned long long)trace->cr0, (unsigned long long)trace->cr4,
          (unsigned long long)trace->efer, (unsigned long long)trace->rflags,
          (unsigned long long)trace->rip, (unsigned long long)trace->rsp);
  fprintf(stderr, "kvmd: terminal-entry gdt=%08x:%04x idt=%08x:%04x", trace->gdt_base,
          (unsigned)trace->gdt_limit, trace->idt_base, (unsigned)trace->idt_limit);
  fail_entry_trace_segment(stderr, "cs", &trace->cs);
  fail_entry_trace_segment(stderr, "ds", &trace->ds);
  fail_entry_trace_segment(stderr, "es", &trace->es);
  fail_entry_trace_segment(stderr, "ss", &trace->ss);
  fail_entry_trace_segment(stderr, "ldt", &trace->ldt);
  fail_entry_trace_segment(stderr, "tr", &trace->tr);
  if (trace->exception_gate_valid) {
    fprintf(stderr, " idt[%02x]=", DAZE_KVM_FAIL_ENTRY_TRACE_EXCEPTION_VECTOR);
    for (size_t index = 0; index < sizeof(trace->exception_gate); ++index)
      fprintf(stderr, "%02x", trace->exception_gate[index]);
  } else {
    fprintf(stderr, " idt[%02x]=absent", DAZE_KVM_FAIL_ENTRY_TRACE_EXCEPTION_VECTOR);
  }
  fprintf(stderr, " stack=%s", trace->stack_linear_valid ? "present" : "absent");
  if (trace->stack_linear_valid) {
    fprintf(stderr, ":%08x", trace->stack_linear);
    for (uint32_t index = 0; index < trace->stack_word_count; ++index)
      fprintf(stderr, "%s %04x", index == 0 ? ":" : "", trace->stack_words[index]);
  }
  fputc('\n', stderr);
  fprintf(stderr, "kvmd: terminal-entry instruction@%08x", trace->cs.base + (uint32_t)trace->rip);
  for (uint32_t index = 0; index < trace->instruction_count; ++index)
    fprintf(stderr, "%s%02x", index == 0 ? ":" : "", trace->instruction_bytes[index]);
  fputc('\n', stderr);
  const uint32_t context_start = trace->cs.base + (uint32_t)trace->rip >= 0x40u
                                   ? trace->cs.base + (uint32_t)trace->rip - 0x40u
                                   : 0u;
  fprintf(stderr, "kvmd: terminal-entry context@%08x", context_start);
  for (uint32_t index = 0; index < trace->context_count; ++index)
    fprintf(stderr, "%s%02x", index == 0 ? ":" : "", trace->context_bytes[index]);
  fputc('\n', stderr);
  if (trace->handler_descriptor_valid) {
    fprintf(stderr, "kvmd: terminal-entry gdt[%02x]=", DAZE_KVM_FAIL_ENTRY_TRACE_HANDLER_INDEX);
    for (size_t index = 0; index < sizeof(trace->handler_descriptor); ++index)
      fprintf(stderr, "%02x", trace->handler_descriptor[index]);
    fputc('\n', stderr);
  }
  if (trace->code_descriptor_valid) {
    fprintf(stderr, "kvmd: terminal-entry ldt[%02x]=", DAZE_KVM_FAIL_ENTRY_TRACE_CODE_INDEX);
    for (size_t index = 0; index < sizeof(trace->code_descriptor); ++index)
      fprintf(stderr, "%02x", trace->code_descriptor[index]);
    fputc('\n', stderr);
  }
  if (trace->target_descriptor_valid) {
    fprintf(stderr, "kvmd: terminal-entry ldt[%02x]=", DAZE_KVM_FAIL_ENTRY_TRACE_TARGET_INDEX);
    for (size_t index = 0; index < sizeof(trace->target_descriptor); ++index)
      fprintf(stderr, "%02x", trace->target_descriptor[index]);
    fputc('\n', stderr);
  }
  if (trace->handler_code_valid) {
    fprintf(stderr, "kvmd: terminal-entry handler-code");
    for (uint32_t index = 0; index < trace->handler_code_count; ++index)
      fprintf(stderr, "%s%02x", index == 0 ? ":" : "", trace->handler_code[index]);
    fputc('\n', stderr);
  }
}

static int mediator_pio(const DazeKvmDpmiEntryResult *result) {
  return result->observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
         result->observation.pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
         result->observation.pio_port == DAZE_KVM_DPMI_MEDIATOR_PORT &&
         result->observation.pio_size == 1 && result->observation.pio_count == 1 &&
         result->observation.pio_value_present &&
         (uint8_t)result->observation.pio_value == DAZE_KVM_DPMI_MEDIATOR_MARKER;
}

static int timed_kvm_run(DazeKvmMachine *machine, unsigned kind) {
  DazeRunMetrics *const metrics = machine->run_metrics;
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const int status = ioctl(machine->vcpu, KVM_RUN, 0);
  if (metrics == NULL || !metrics->enabled) return status;
  const uint64_t finished = monotonic_nanoseconds();
  metrics->kvm_dpmi_run_calls[kind]++;
  const uint64_t elapsed = finished >= started ? finished - started : 0;
  metrics->kvm_dpmi_run_nanoseconds[kind] += elapsed;
  if (status == 0) {
    const struct kvm_run *run = machine->run;
    const unsigned exit = run->exit_reason == KVM_EXIT_DEBUG ? DAZE_RUN_METRICS_KVM_EXIT_DEBUG
                          : run->exit_reason == KVM_EXIT_IO  ? DAZE_RUN_METRICS_KVM_EXIT_IO
                          : run->exit_reason == KVM_EXIT_HLT ? DAZE_RUN_METRICS_KVM_EXIT_HLT
                                                             : DAZE_RUN_METRICS_KVM_EXIT_OTHER;
    metrics->kvm_dpmi_run_exit_calls[kind][exit]++;
    metrics->kvm_dpmi_run_exit_nanoseconds[kind][exit] += elapsed;
    if (run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT &&
        run->io.size == 1 && run->io.count == 1 && run->io.data_offset <= machine->run_size &&
        run->io.size <= machine->run_size - run->io.data_offset) {
      const uint8_t marker = *((const uint8_t *)run + run->io.data_offset);
      metrics->kvm_dpmi_io_marker_calls[marker]++;
      metrics->kvm_dpmi_io_marker_nanoseconds[marker] += elapsed;
    }
  }
  return status;
}

static int timed_set_guest_debug(DazeKvmMachine *machine, const struct kvm_guest_debug *debug) {
  DazeRunMetrics *const metrics = machine->run_metrics;
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const int status = ioctl(machine->vcpu, KVM_SET_GUEST_DEBUG, debug);
  if (metrics != NULL && metrics->enabled) {
    const uint64_t finished = monotonic_nanoseconds();
    metrics->kvm_dpmi_debug_update_calls++;
    if (finished >= started) metrics->kvm_dpmi_debug_update_nanoseconds += finished - started;
  }
  return status;
}

static int range_valid(const DazeKvmMachine *machine, uint32_t address, size_t size) {
  return machine != NULL && machine->guest != NULL &&
         daze_kvm_range_fits(machine->guest_size, address, size);
}

static int layout_valid(const DazeKvmMachine *machine, const DazeKvmRunnerDpmiHandoff *handoff,
                        const DazeKvmDpmiEntryLayout *layout) {
  if (handoff == NULL || !handoff->valid || layout == NULL || layout->write_count == 0 ||
      layout->writes == NULL || !range_valid(machine, layout->mailbox_address, 16) ||
      !range_valid(machine, layout->terminal_linear, 1))
    return 0;
  for (size_t index = 0; index < layout->write_count; ++index) {
    const DazeKvmGuestWrite *write = layout->writes + index;
    if (write->bytes == NULL || write->size == 0 ||
        !range_valid(machine, write->address, write->size))
      return 0;
  }
  return 1;
}

static int clear_guest_debug(DazeKvmMachine *machine) {
  const struct kvm_guest_debug disabled = {0};
  return timed_set_guest_debug(machine, &disabled);
}

static void observe_exit(const DazeKvmMachine *machine, const struct kvm_run *run,
                         DazeKvmDpmiEntryObservation *observation) {
  observation->raw_exit_reason = run->exit_reason;
  switch (run->exit_reason) {
  case KVM_EXIT_DEBUG:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_DEBUG;
    break;
  case KVM_EXIT_IO:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_PIO;
    observation->pio_port = run->io.port;
    observation->pio_direction = run->io.direction == KVM_EXIT_IO_IN ? DAZE_KVM_DPMI_ENTRY_PIO_IN
                                                                     : DAZE_KVM_DPMI_ENTRY_PIO_OUT;
    observation->pio_size = run->io.size;
    observation->pio_count = run->io.count;
    if (run->io.direction == KVM_EXIT_IO_OUT && run->io.count == 1 &&
        run->io.size <= sizeof(observation->pio_value) &&
        run->io.data_offset <= machine->run_size &&
        run->io.size <= machine->run_size - run->io.data_offset) {
      memcpy(&observation->pio_value, (const uint8_t *)run + run->io.data_offset, run->io.size);
      observation->pio_value_present = 1;
    }
    break;
  case KVM_EXIT_HLT:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_HLT;
    break;
  case KVM_EXIT_FAIL_ENTRY:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_FAIL_ENTRY;
    observation->fail_entry_reason = run->fail_entry.hardware_entry_failure_reason;
    break;
  case KVM_EXIT_INTERNAL_ERROR:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_OTHER;
    observation->internal_suberror = run->internal.suberror;
    break;
  default:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_OTHER;
    break;
  }
}

static void observe_continuation_exit(const DazeKvmMachine *machine, const struct kvm_run *run,
                                      DazeKvmDpmiEntryObservation *observation) {
  observe_exit(machine, run, observation);
  switch (observation->kind) {
  case DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_DEBUG:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_DEBUG;
    break;
  case DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_PIO:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO;
    break;
  case DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_HLT:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_HLT;
    break;
  case DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_FAIL_ENTRY:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_FAIL_ENTRY;
    break;
  case DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_OTHER:
    observation->kind = DAZE_KVM_DPMI_ENTRY_EXIT_OTHER;
    break;
  default:
    break;
  }
}

/* Terminal diagnostics read parked CPU state without resuming or modifying it. */
static void report_terminal_entry_once(DazeKvmMachine *machine,
                                       const DazeKvmDpmiEntryObservation *observation) {
  static int reported;
  if (reported || !fail_entry_trace_armed() || machine == NULL || machine->vcpu < 0 ||
      observation == NULL)
    return;
  if (observation->kind != DAZE_KVM_DPMI_ENTRY_EXIT_FAIL_ENTRY &&
      observation->kind != DAZE_KVM_DPMI_ENTRY_EXIT_OTHER)
    return;
  reported = 1;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (ioctl(machine->vcpu, KVM_GET_REGS, &regs) < 0 ||
      ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0) {
    fprintf(stderr, "kvmd: terminal-entry unavailable exit=%u/%s errno=%d\n",
            observation->raw_exit_reason,
            daze_kvm_dpmi_entry_fail_entry_trace_exit_name(observation->raw_exit_reason), errno);
    return;
  }
  DazeKvmFailEntryTraceSegment segments[4];
  const struct kvm_segment *const reported_segments[4] = {&sregs.cs, &sregs.ds, &sregs.es,
                                                          &sregs.ss};
  for (size_t index = 0; index < 4; ++index)
    segments[index] = (DazeKvmFailEntryTraceSegment){
      .selector = reported_segments[index]->selector,
      .base = (uint32_t)reported_segments[index]->base,
      .limit = reported_segments[index]->limit,
      .type = (uint16_t)(reported_segments[index]->present ? 0x80u : 0u) |
              (uint16_t)(reported_segments[index]->type & 0x0fu),
      .db = (uint8_t)reported_segments[index]->db};
  DazeKvmFailEntryTrace trace = {
    .raw_exit_reason = observation->raw_exit_reason,
    .hardware_entry_failure_reason = observation->fail_entry_reason,
    .hardware_entry_failure_reason_present =
      observation->kind == DAZE_KVM_DPMI_ENTRY_EXIT_FAIL_ENTRY,
    .cr0 = sregs.cr0,
    .cr4 = sregs.cr4,
    .efer = sregs.efer,
    .rflags = regs.rflags,
    .rip = regs.rip,
    .rsp = regs.rsp,
    .cs = segments[0],
    .ds = segments[1],
    .es = segments[2],
    .ss = segments[3],
    .gdt_base = (uint32_t)sregs.gdt.base,
    .gdt_limit = sregs.gdt.limit,
    .idt_base = (uint32_t)sregs.idt.base,
    .idt_limit = sregs.idt.limit,
    .ldt = {.selector = sregs.ldt.selector,
            .base = (uint32_t)sregs.ldt.base,
            .limit = sregs.ldt.limit,
            .type = (uint16_t)(sregs.ldt.present ? 0x80u : 0u) | (uint16_t)(sregs.ldt.type & 0x0fu),
            .db = (uint8_t)sregs.ldt.db},
    .tr = {.selector = sregs.tr.selector,
           .base = (uint32_t)sregs.tr.base,
           .limit = sregs.tr.limit,
           .type = (uint16_t)(sregs.tr.present ? 0x80u : 0u) | (uint16_t)(sregs.tr.type & 0x0fu),
           .db = (uint8_t)sregs.tr.db}};
  daze_kvm_dpmi_entry_fail_entry_trace_capture(&trace, (const uint8_t *)machine->guest,
                                               machine->guest_size);
  daze_kvm_dpmi_entry_fail_entry_trace_report(&trace);
}

static int capture_state(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result, unsigned kind) {
  DazeRunMetrics *const metrics = machine->run_metrics;
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  /* Post-KVM_RUN exit state only; callers capture immediately after a run,
   * never before the first one. */
  const int captured = daze_kvm_machine_get_regs(machine, &regs) == DAZE_KVM_MACHINE_OK &&
                       daze_kvm_machine_get_sregs(machine, &sregs) == DAZE_KVM_MACHINE_OK;
  if (metrics != NULL && metrics->enabled) {
    const uint64_t finished = monotonic_nanoseconds();
    metrics->kvm_dpmi_state_capture_calls[kind]++;
    if (finished >= started)
      metrics->kvm_dpmi_state_capture_nanoseconds[kind] += finished - started;
  }
  if (!captured) {
    result->observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_CAPTURE_FAILED;
    return 0;
  }
  result->cr0 = (uint32_t)sregs.cr0;
  result->cr4 = (uint32_t)sregs.cr4;
  result->efer = sregs.efer;
  result->rip = (uint32_t)regs.rip;
  result->rflags = (uint32_t)regs.rflags;
  result->cs = sregs.cs.selector;
  result->cs_base = (uint32_t)sregs.cs.base;
  result->ss = sregs.ss.selector;
  result->ss_base = (uint32_t)sregs.ss.base;
  result->ss_limit = sregs.ss.limit;
  result->ss_db = sregs.ss.db;
  result->ss_type = sregs.ss.type;
  result->ss_present = sregs.ss.present;
  result->ds_base = (uint32_t)sregs.ds.base;
  result->es_base = (uint32_t)sregs.es.base;
  result->fs_base = (uint32_t)sregs.fs.base;
  result->gs_base = (uint32_t)sregs.gs.base;
  result->esp = (uint32_t)regs.rsp;
  result->cs_db = sregs.cs.db;
  report_terminal_entry_once(machine, &result->observation);
  result->idt_base = (uint32_t)sregs.idt.base;
  result->idt_limit = sregs.idt.limit;
  result->gdt_base = (uint32_t)sregs.gdt.base;
  result->gdt_limit = sregs.gdt.limit;
  result->ldt_base = (uint32_t)sregs.ldt.base;
  result->ldt_limit = sregs.ldt.limit;
  result->ldt = sregs.ldt.selector;
  result->ldt_type = sregs.ldt.type;
  result->ldt_present = sregs.ldt.present;
  result->tr_base = (uint32_t)sregs.tr.base;
  result->tr_limit = sregs.tr.limit;
  result->tr = sregs.tr.selector;
  result->tr_type = sregs.tr.type;
  result->tr_present = sregs.tr.present;
  result->sp = (uint16_t)regs.rsp;
  result->ax = (uint16_t)regs.rax;
  result->bx = (uint16_t)regs.rbx;
  result->cx = (uint16_t)regs.rcx;
  result->dx = (uint16_t)regs.rdx;
  result->si = (uint16_t)regs.rsi;
  result->di = (uint16_t)regs.rdi;
  result->ds = sregs.ds.selector;
  result->es = sregs.es.selector;
  result->fs = sregs.fs.selector;
  result->gs = sregs.gs.selector;
  const uint32_t instruction_address = result->cs_base + result->rip;
  if (instruction_address >= result->cs_base &&
      daze_kvm_range_fits(machine->guest_size, instruction_address, sizeof(result->instruction))) {
    memcpy(result->instruction, (const uint8_t *)machine->guest + instruction_address,
           sizeof(result->instruction));
    result->instruction_size = sizeof(result->instruction);
  }
  return 1;
}

static int clear_after_run(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result) {
  if (clear_guest_debug(machine) == 0) return 0;
  result->observation.clear_error = errno;
  return 1;
}

int daze_kvm_dpmi_entry_run(DazeKvmMachine *machine, const DazeKvmRunnerDpmiHandoff *handoff,
                            const DazeKvmDpmiEntryLayout *layout, DazeKvmDpmiEntryResult *result) {
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  if (result == NULL || !layout_valid(machine, handoff, layout)) return DAZE_KVM_DPMI_ENTRY_INVALID;
  struct kvm_guest_debug debug = {.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP};
  debug.arch.debugreg[0] = layout->terminal_linear;
  debug.arch.debugreg[7] = 3;
  if (timed_set_guest_debug(machine, &debug) < 0) return DAZE_KVM_DPMI_ENTRY_FAILED;
  for (size_t index = 0; index < layout->write_count; ++index) {
    const DazeKvmGuestWrite *write = layout->writes + index;
    memcpy((uint8_t *)machine->guest + write->address, write->bytes, write->size);
  }
  uint8_t *mailbox = (uint8_t *)machine->guest + layout->mailbox_address;
  daze_write_u16(mailbox, handoff->ax);
  daze_write_u16(mailbox + 2, handoff->bx);
  daze_write_u16(mailbox + 4, handoff->cx);
  daze_write_u16(mailbox + 6, handoff->dx);
  daze_write_u16(mailbox + 8, handoff->si);
  daze_write_u16(mailbox + 10, handoff->di);
  daze_write_u16(mailbox + 12, handoff->es);
  daze_write_u16(mailbox + 14, handoff->flags);
  const struct kvm_run *run = (const struct kvm_run *)machine->run;
  if (timed_kvm_run(machine, DAZE_RUN_METRICS_DPMI_RUN_ENTRY) < 0) {
    result->observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_RUN_FAILED;
    result->observation.run_error = errno;
    (void)clear_after_run(machine, result);
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  if (run->exit_reason != KVM_EXIT_DEBUG || run->debug.arch.pc != layout->terminal_linear) {
    observe_exit(machine, run, &result->observation);
    /* A production failure remains terminal.  The opt-in EXEC diagnostic may
     * retain the parked state so a shutdown has a causal CPU boundary. */
    if (getenv("DAZE_EXEC_TRACE") != NULL)
      (void)capture_state(machine, result, DAZE_RUN_METRICS_DPMI_CAPTURE_DIAGNOSTIC);
    (void)clear_after_run(machine, result);
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  result->observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG;
  result->observation.raw_exit_reason = run->exit_reason;
  if (!capture_state(machine, result, DAZE_RUN_METRICS_DPMI_CAPTURE_ENTRY)) {
    (void)clear_after_run(machine, result);
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  if (clear_after_run(machine, result)) return DAZE_KVM_DPMI_ENTRY_FAILED;
  return DAZE_KVM_DPMI_ENTRY_OK;
}

int daze_kvm_dpmi_entry_continue_once(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result) {
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  if (machine == NULL || machine->vcpu < 0 || machine->run == NULL || result == NULL)
    return DAZE_KVM_DPMI_ENTRY_INVALID;
  if (timed_kvm_run(machine, DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_ONCE) < 0) {
    result->observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_RUN_FAILED;
    result->observation.run_error = errno;
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  observe_continuation_exit(machine, (const struct kvm_run *)machine->run, &result->observation);
  return capture_state(machine, result, DAZE_RUN_METRICS_DPMI_CAPTURE_CONTINUE_ONCE)
           ? DAZE_KVM_DPMI_ENTRY_OK
           : DAZE_KVM_DPMI_ENTRY_FAILED;
}

int daze_kvm_dpmi_entry_continue_mediator_or_capture(DazeKvmMachine *machine,
                                                     DazeKvmDpmiEntryResult *result) {
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  if (machine == NULL || machine->vcpu < 0 || machine->run == NULL || result == NULL)
    return DAZE_KVM_DPMI_ENTRY_INVALID;
  if (timed_kvm_run(machine, DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_ONCE) < 0) {
    result->observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_RUN_FAILED;
    result->observation.run_error = errno;
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  observe_continuation_exit(machine, (const struct kvm_run *)machine->run, &result->observation);
  if (mediator_pio(result)) {
    if (machine->run_metrics != NULL && machine->run_metrics->enabled)
      machine->run_metrics->kvm_dpmi_mediator_capture_elisions++;
    return DAZE_KVM_DPMI_ENTRY_OK;
  }
  return capture_state(machine, result, DAZE_RUN_METRICS_DPMI_CAPTURE_CONTINUE_ONCE)
           ? DAZE_KVM_DPMI_ENTRY_OK
           : DAZE_KVM_DPMI_ENTRY_FAILED;
}

int daze_kvm_dpmi_entry_continue_observe(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result) {
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  if (machine == NULL || machine->vcpu < 0 || machine->run == NULL || result == NULL)
    return DAZE_KVM_DPMI_ENTRY_INVALID;
  if (timed_kvm_run(machine, DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_OBSERVE) < 0) {
    result->observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_RUN_FAILED;
    result->observation.run_error = errno;
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  observe_continuation_exit(machine, (const struct kvm_run *)machine->run, &result->observation);
  return DAZE_KVM_DPMI_ENTRY_OK;
}

int daze_kvm_dpmi_entry_capture_state(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result) {
  if (result == NULL) return DAZE_KVM_DPMI_ENTRY_INVALID;
  return capture_state(machine, result, DAZE_RUN_METRICS_DPMI_CAPTURE_TERMINAL)
           ? DAZE_KVM_DPMI_ENTRY_OK
           : DAZE_KVM_DPMI_ENTRY_FAILED;
}

static int continue_to_linear(DazeKvmMachine *machine, uint32_t linear,
                              DazeKvmDpmiEntryResult *result, int capture) {
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  if (machine == NULL || machine->vcpu < 0 || machine->run == NULL || result == NULL ||
      !range_valid(machine, linear, 1))
    return DAZE_KVM_DPMI_ENTRY_INVALID;
  struct kvm_guest_debug debug = {.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP};
  debug.arch.debugreg[0] = linear;
  debug.arch.debugreg[7] = 3;
  if (timed_set_guest_debug(machine, &debug) < 0) return DAZE_KVM_DPMI_ENTRY_FAILED;
  if (timed_kvm_run(machine, DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_TO_LINEAR) < 0) {
    result->observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_RUN_FAILED;
    result->observation.run_error = errno;
    (void)clear_after_run(machine, result);
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  const struct kvm_run *run = (const struct kvm_run *)machine->run;
  if (run->exit_reason != KVM_EXIT_DEBUG || run->debug.arch.pc != linear) {
    observe_exit(machine, run, &result->observation);
    (void)clear_after_run(machine, result);
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  result->observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG;
  result->observation.raw_exit_reason = run->exit_reason;
  if (capture &&
      !capture_state(machine, result, DAZE_RUN_METRICS_DPMI_CAPTURE_CONTINUE_TO_LINEAR)) {
    (void)clear_after_run(machine, result);
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  return clear_after_run(machine, result) ? DAZE_KVM_DPMI_ENTRY_FAILED : DAZE_KVM_DPMI_ENTRY_OK;
}

int daze_kvm_dpmi_entry_continue_to_linear(DazeKvmMachine *machine, uint32_t linear,
                                           DazeKvmDpmiEntryResult *result) {
  return continue_to_linear(machine, linear, result, 1);
}

static int retire_mediator_out(DazeKvmMachine *machine, uint32_t cs_base, uint32_t rip,
                               DazeKvmDpmiEntryResult *result, int capture) {
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  if (machine == NULL || machine->vcpu < 0 || machine->run == NULL || result == NULL ||
      machine->guest == NULL)
    return DAZE_KVM_DPMI_ENTRY_INVALID;
  const uint32_t parked = cs_base + rip;
  if (parked < cs_base || !range_valid(machine, parked, 8)) return DAZE_KVM_DPMI_ENTRY_INVALID;
  const uint8_t *bytes = (const uint8_t *)machine->guest + parked;
  if (bytes[0] != 0xe6 || bytes[1] != (uint8_t)DAZE_KVM_DPMI_MEDIATOR_PORT)
    return DAZE_KVM_DPMI_ENTRY_INVALID;
  struct kvm_regs parked_regs;
  /* Sync reads are fresh after a mediator exit. EXEC restoration may install registers
   * with raw ioctls, so its capture path must read kernel state. */
  const int regs_ok = capture
                        ? ioctl(machine->vcpu, KVM_GET_REGS, &parked_regs) == 0
                        : daze_kvm_machine_get_regs(machine, &parked_regs) == DAZE_KVM_MACHINE_OK;
  if (!regs_ok || ((uint8_t)parked_regs.rax != DAZE_KVM_DPMI_MEDIATOR_MARKER &&
                   (uint8_t)parked_regs.rax != DAZE_KVM_PROTECTED_DOS_MARKER))
    return DAZE_KVM_DPMI_ENTRY_INVALID;
  const uint64_t successor = (uint64_t)parked + 2;
  if (successor >= machine->guest_size) return DAZE_KVM_DPMI_ENTRY_INVALID;
  if (!capture) {
    /* The validated two-byte OUT writes a dummy port; advancing RIP retires it without
     * executing guest code or changing other state. */
    parked_regs.rip = (uint64_t)rip + 2;
    return ioctl(machine->vcpu, KVM_SET_REGS, &parked_regs) == 0 ? DAZE_KVM_DPMI_ENTRY_OK
                                                                 : DAZE_KVM_DPMI_ENTRY_FAILED;
  }
  if (continue_to_linear(machine, (uint32_t)successor, result, capture) != DAZE_KVM_DPMI_ENTRY_OK)
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  if (result->observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG)
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  if (capture && (result->rip != rip + 2 || result->cs_base != cs_base))
    return DAZE_KVM_DPMI_ENTRY_FAILED;
  return DAZE_KVM_DPMI_ENTRY_OK;
}

int daze_kvm_dpmi_entry_retire_mediator_out(DazeKvmMachine *machine, uint32_t cs_base, uint32_t rip,
                                            DazeKvmDpmiEntryResult *result) {
  return retire_mediator_out(machine, cs_base, rip, result, 1);
}

int daze_kvm_dpmi_entry_retire_mediator_out_observe(DazeKvmMachine *machine, uint32_t cs_base,
                                                    uint32_t rip, DazeKvmDpmiEntryResult *result) {
  return retire_mediator_out(machine, cs_base, rip, result, 0);
}

#else
int daze_kvm_dpmi_entry_run(DazeKvmMachine *machine, const DazeKvmRunnerDpmiHandoff *handoff,
                            const DazeKvmDpmiEntryLayout *layout, DazeKvmDpmiEntryResult *result) {
  (void)machine;
  (void)handoff;
  (void)layout;
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  return DAZE_KVM_DPMI_ENTRY_UNAVAILABLE;
}

int daze_kvm_dpmi_entry_continue_once(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result) {
  (void)machine;
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  return DAZE_KVM_DPMI_ENTRY_UNAVAILABLE;
}

int daze_kvm_dpmi_entry_continue_mediator_or_capture(DazeKvmMachine *machine,
                                                     DazeKvmDpmiEntryResult *result) {
  (void)machine;
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  return DAZE_KVM_DPMI_ENTRY_UNAVAILABLE;
}

int daze_kvm_dpmi_entry_continue_observe(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result) {
  (void)machine;
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  return DAZE_KVM_DPMI_ENTRY_UNAVAILABLE;
}

int daze_kvm_dpmi_entry_capture_state(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result) {
  (void)machine;
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  return DAZE_KVM_DPMI_ENTRY_UNAVAILABLE;
}

int daze_kvm_dpmi_entry_continue_to_linear(DazeKvmMachine *machine, uint32_t linear,
                                           DazeKvmDpmiEntryResult *result) {
  (void)machine;
  (void)linear;
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  return DAZE_KVM_DPMI_ENTRY_UNAVAILABLE;
}

int daze_kvm_dpmi_entry_retire_mediator_out(DazeKvmMachine *machine, uint32_t cs_base, uint32_t rip,
                                            DazeKvmDpmiEntryResult *result) {
  (void)machine;
  (void)cs_base;
  (void)rip;
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  return DAZE_KVM_DPMI_ENTRY_UNAVAILABLE;
}

int daze_kvm_dpmi_entry_retire_mediator_out_observe(DazeKvmMachine *machine, uint32_t cs_base,
                                                    uint32_t rip, DazeKvmDpmiEntryResult *result) {
  (void)machine;
  (void)cs_base;
  (void)rip;
  if (result != NULL) *result = (DazeKvmDpmiEntryResult){0};
  return DAZE_KVM_DPMI_ENTRY_UNAVAILABLE;
}

#endif
