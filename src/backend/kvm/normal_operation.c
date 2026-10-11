#include "normal_operation.h"

#include "owner.h"
#include "result.h"
#include "entry.h"
#include "normal_config.h"
#include "runner_private.h"
#include "runner/runner_private.h"
#include "guest_memory_layout.h"

#include <stdio.h>
#include <stdlib.h>

/* Diagnostic-only: DAZE_KVM_POST_SUCCESSOR_TRACE prints the retained owner's
 * protected-gate terminal and its last fault/vector state without changing the
 * command result. */
static void trace_owner_terminal(const DazeKvmCommandOwnerResult *owner) {
  const DazeKvmDpmiEntryResult *terminal = &owner->protected_gate.terminal;
  fprintf(stderr,
          "kvmd: owner=%d stage=%d transition=%d gate_present=%d gate_status=%d exchanges=%zu\n",
          owner->disposition, owner->transition_stage, owner->transition_status,
          owner->protected_gate_present, owner->protected_gate_status,
          owner->protected_gate.exchange_count);
  const DazeKvmDpmiEntryResult *transition = &owner->transition_successor;
  fprintf(stderr,
          "kvmd: transition-successor cs:ip=%04x:%08x db=%u kind=%d raw=%u runerr=%d "
          "pio=%04x:%u:%u:%u ax=%04x bx=%04x cx=%04x dx=%04x ds=%04x es=%04x ss=%04x sp=%04x\n",
          transition->cs, transition->rip, transition->cs_db, transition->observation.kind,
          transition->observation.raw_exit_reason, transition->observation.run_error,
          transition->observation.pio_port, transition->observation.pio_direction,
          transition->observation.pio_size, transition->observation.pio_value, transition->ax,
          transition->bx, transition->cx, transition->dx, transition->ds, transition->es,
          transition->ss, transition->sp);
  if (owner->protected_gate_present) {
    fprintf(stderr,
            "kvmd: gate-terminal cs:ip=%04x:%08x db=%u kind=%d raw=%u ax=%04x bx=%04x cx=%04x "
            "dx=%04x si=%04x di=%04x ds=%04x es=%04x ss=%04x sp=%04x cs_base=%08x ss_base=%08x "
            "es_base=%08x gdt=%08x idt=%08x bytes",
            terminal->cs, terminal->rip, terminal->cs_db, terminal->observation.kind,
            terminal->observation.raw_exit_reason, terminal->ax, terminal->bx, terminal->cx,
            terminal->dx, terminal->si, terminal->di, terminal->ds, terminal->es, terminal->ss,
            terminal->sp, terminal->cs_base, terminal->ss_base, terminal->es_base,
            terminal->gdt_base, terminal->idt_base);
    for (size_t byte = 0; byte < terminal->instruction_size; ++byte)
      fprintf(stderr, " %02x", terminal->instruction[byte]);
    fputc('\n', stderr);
  }
  const DazeKvmDpmiEntryResult *post = &owner->post_successor;
  fprintf(stderr,
          "kvmd: post-successor cs:ip=%04x:%08x db=%u kind=%d raw=%u ax=%04x bx=%04x cx=%04x "
          "dx=%04x si=%04x di=%04x ds=%04x es=%04x ss=%04x sp=%04x cs_base=%08x ss_base=%08x "
          "es_base=%08x\n",
          post->cs, post->rip, post->cs_db, post->observation.kind,
          post->observation.raw_exit_reason, post->ax, post->bx, post->cx, post->dx, post->si,
          post->di, post->ds, post->es, post->ss, post->sp, post->cs_base, post->ss_base,
          post->es_base);
  if (owner->post_return_request_present)
    fprintf(stderr, "kvmd: post-return fn=%04x sel=%04x operand=%08x\n",
            owner->post_return_function, owner->post_return_selector, owner->post_return_operand);
  if (owner->terminal_vector21_idt_entry_present)
    fprintf(stderr, "kvmd: vector21-idt %02x %02x %02x %02x %02x %02x %02x %02x\n",
            owner->terminal_vector21_idt_entry[0], owner->terminal_vector21_idt_entry[1],
            owner->terminal_vector21_idt_entry[2], owner->terminal_vector21_idt_entry[3],
            owner->terminal_vector21_idt_entry[4], owner->terminal_vector21_idt_entry[5],
            owner->terminal_vector21_idt_entry[6], owner->terminal_vector21_idt_entry[7]);
  if (owner->terminal_fault_stack_present) {
    fputs("kvmd: fault-stack", stderr);
    for (size_t index = 0; index < sizeof(owner->terminal_fault_stack); ++index)
      fprintf(stderr, " %02x", owner->terminal_fault_stack[index]);
    fputc('\n', stderr);
  }
  for (size_t index = 0; index < owner->protected_gate.exchange_count; ++index) {
    const DazeKvmProtectedGateExchange *exchange = owner->protected_gate.exchanges + index;
    fprintf(
      stderr, "kvmd: exchange=%zu fn=%04x sel=%04x client=%04x:%04x reply=%08x/%08x/%08x/%08x\n",
      index + 1, exchange->function, exchange->selector, exchange->client_cs, exchange->client_ip,
      exchange->reply_ax, exchange->reply_bx, exchange->reply_cx, exchange->reply_dx);
  }
}

static int normal_placement_matches(const DazeKvmRunnerRequestCommon *request) {
  return request != NULL && request->psp_segment == k_psp_segment &&
         request->environment_segment == k_environment_segment &&
         request->dpmi_entry_segment == k_dpmi_entry_segment &&
         request->dos_vector_segment == k_dos_int21_vector_segment &&
         request->load_segment == k_load_segment && request->guest_size == k_memory_size;
}

int daze_kvm_normal_operation_request_valid(const DazeKvmRunnerRequestCommon *request) {
  return normal_placement_matches(request) && daze_kvm_runner_process_valid(request);
}

static DazeCommandResult normalize(const DazeKvmCommandOwnerResult *owner) {
  return daze_kvm_command_result_normalize(&(DazeKvmCommandNormalizerInput){
    .disposition = owner->disposition,
    .guest_execution_started = owner->guest_execution_may_have_started,
    .exit_status_present = owner->guest_exit_status_present,
    .exit_status = owner->guest_exit_status});
}

static void observe_owner(const DazeKvmCommandOwnerResult *owner,
                          DazeKvmNormalOperationObservation *observation) {
  if (observation == NULL || owner == NULL || !owner->post_successor_present) return;
  const DazeKvmDpmiEntryResult *boundary = &owner->post_successor;
  *observation = (DazeKvmNormalOperationObservation){
    .present = 1,
    .source = 2,
    .owner_disposition = owner->disposition,
    .exit_kind = boundary->observation.kind,
    .raw_exit_reason = boundary->observation.raw_exit_reason,
    .pio_port = boundary->observation.pio_port,
    .pio_direction = (uint8_t)boundary->observation.pio_direction,
    .pio_size = boundary->observation.pio_size,
    .pio_value_present = boundary->observation.pio_value_present,
    .pio_value = boundary->observation.pio_value,
    .cs = boundary->cs,
    .rip = boundary->rip,
    .cs_base = boundary->cs_base,
    .ss_base = boundary->ss_base,
    .es_base = boundary->es_base,
    .gdt_base = boundary->gdt_base,
    .idt_base = boundary->idt_base,
    .ax = boundary->ax,
    .bx = boundary->bx,
    .cx = boundary->cx,
    .dx = boundary->dx,
    .ds = boundary->ds,
    .es = boundary->es,
    .ss = boundary->ss,
    .sp = boundary->sp,
    .transition_stage = owner->transition_stage,
    .transition_status = owner->transition_status,
    .protected_gate_status = owner->protected_gate_status,
    .post_return_request_present = owner->post_return_request_present,
    .post_return_function = owner->post_return_function,
    .post_return_selector = owner->post_return_selector,
    .post_return_operand = owner->post_return_operand,
    .post_return_gate_status = owner->post_return_gate_status,
    .runner_request_present = owner->terminal_runner_request_present,
    .runner_vector = owner->terminal_runner_request.vector,
    .runner_ax = owner->terminal_runner_request.ax,
    .runner_bx = owner->terminal_runner_request.bx,
    .runner_cx = owner->terminal_runner_request.cx,
    .runner_dx = owner->terminal_runner_request.dx,
    .runner_ds = owner->terminal_runner_request.ds,
    .runner_es = owner->terminal_runner_request.es,
    .runner_si = owner->terminal_runner_request.si,
    .runner_di = owner->terminal_runner_request.di,
  };
}

DazeCommandResult
daze_kvm_normal_operation_run_observe(const DazeKvmRunnerRequestCommon *request,
                                      DazeKvmMachine *machine,
                                      DazeKvmNormalOperationObservation *observation) {
  if (observation != NULL) *observation = (DazeKvmNormalOperationObservation){0};
  DazeKvmCommandOwnerResult owner = {.disposition = DAZE_KVM_COMMAND_OWNER_PRESTART_REJECTED};
  if (!daze_kvm_normal_operation_request_valid(request)) return normalize(&owner);

  DazeKvmCommandOwnerHandoff handoff = {0};
  const DazeKvmRunnerGenericPreflightRequest preflight = {.process = *request};
  DazeKvmRunnerGenericPreflightResult preflight_observation;
  const int begin_status =
    daze_kvm_command_owner_begin_observe(&preflight, machine, &handoff, &preflight_observation);
  if (begin_status != DAZE_KVM_COMMAND_OWNER_HANDOFF_OK) {
    if (begin_status == DAZE_KVM_COMMAND_OWNER_HANDOFF_EXEC) {
      DazeDpmiProcessState state = {0};
      owner.disposition = daze_kvm_command_owner_start_exec(&handoff, &preflight, &state, &owner);
      daze_kvm_command_owner_handoff_destroy(&handoff);
      observe_owner(&owner, observation);
      return normalize(&owner);
    }
    if (begin_status == DAZE_KVM_COMMAND_OWNER_HANDOFF_TERMINATED) {
      owner.disposition = DAZE_KVM_COMMAND_OWNER_TERMINATED;
      owner.guest_execution_may_have_started = 1;
      owner.guest_exit_status = (uint8_t)preflight_observation.request_ax;
      owner.guest_exit_status_present = 1;
    } else {
      owner.disposition = begin_status == DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED
                            ? DAZE_KVM_COMMAND_OWNER_PRESTART_REJECTED
                            : DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      owner.guest_execution_may_have_started =
        preflight_observation.guest_execution_may_have_started;
    }
    if (observation != NULL) {
      const DazeKvmMachineExitObservation *terminal = &preflight_observation.terminal_observation;
      *observation = (DazeKvmNormalOperationObservation){
        .present = terminal->present,
        .source = 1,
        .capture_status = preflight_observation.terminal_observation_status,
        .owner_disposition = owner.disposition,
        .exit_kind = preflight_observation.disposition,
        .raw_exit_reason = terminal->exit_reason,
        .cs = terminal->cs,
        .rip = (uint32_t)terminal->rip,
        .ax = (uint16_t)terminal->rax,
        .bx = (uint16_t)terminal->rbx,
        .cx = (uint16_t)terminal->rcx,
        .dx = (uint16_t)terminal->rdx,
        .ss = terminal->ss,
        .sp = (uint16_t)terminal->rsp,
        .request_vector = preflight_observation.request_vector,
        .request_ax = preflight_observation.request_ax,
        .request_bx = preflight_observation.request_bx,
        .request_cx = preflight_observation.request_cx,
        .request_dx = preflight_observation.request_dx,
        .request_ds = preflight_observation.request_ds,
      };
    }
    return normalize(&owner);
  }

  const uint32_t image_address = (uint32_t)request->load_segment << 4;
  DazeKvmNormalTransitionConfig config;
  DazeKvmGuestRange runner_reserved[3];
  const size_t runner_reserved_count = runner_reserved_ranges(request->guest_size, runner_reserved);
  const DazeKvmNormalTransitionConfigInput config_input = {
    .guest_size = request->guest_size,
    .resident_image_end = image_address + (uint32_t)request->header->image_size,
    .load_segment = request->load_segment,
    .psp_segment = request->psp_segment,
    .environment_segment = request->environment_segment,
    .dpmi_entry_segment = request->dpmi_entry_segment,
    .dos_int21_vector_segment = request->dos_vector_segment,
    .handoff_ds = handoff.preflight.dpmi_handoff.entry_snapshot.ds,
    .handoff_ss = handoff.preflight.dpmi_handoff.entry_snapshot.ss,
    .handoff_return_ip = handoff.preflight.dpmi_handoff.caller_return_ip,
    .handoff_return_cs = handoff.preflight.dpmi_handoff.caller_return_cs,
    .reserved_ranges = runner_reserved,
    .reserved_range_count = runner_reserved_count,
  };
  DazeKvmNormalTransitionConfigFailure config_failure = {
    DAZE_KVM_NORMAL_TRANSITION_CONFIG_VALID, {0, 0}, {0, 0}};
  if (request->header->image_size > UINT32_MAX - image_address ||
      !daze_kvm_normal_transition_config_build(&config_input, &config, &config_failure)) {
    if (config_failure.kind != DAZE_KVM_NORMAL_TRANSITION_CONFIG_VALID)
      daze_kvm_normal_transition_config_report(&config_input, &config_failure);
    owner.disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    owner.guest_execution_may_have_started = 1;
  } else {
    DazeDpmiProcessState state = {0};
    owner.disposition = daze_kvm_command_owner_continue(
      &handoff,
      &(DazeKvmCommandOwnerInput){
        .preflight = preflight, .transition_layout = config.transition_layout, .state = &state},
      &owner);
    if (getenv("DAZE_KVM_POST_SUCCESSOR_TRACE") != NULL) trace_owner_terminal(&owner);
  }
  daze_kvm_command_owner_handoff_destroy(&handoff);
  observe_owner(&owner, observation);
  return normalize(&owner);
}
