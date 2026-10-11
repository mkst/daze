#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "candidate_observation.h"
#include "backend_runner.h"
#include "machine.h"
#include "metrics.h"
#include "selected_operation.h"
#include "selection_metrics.h"
#include "prepared_request.h"
#if DAZE_HAS_UNICORN
#include "unicorn_run.h"
#endif

#if DAZE_HAS_UNICORN
typedef struct {
  DazePreparedLaunch *launch;
  void *unicorn_context;
  const char *path;
} DazeUnicornPreparedOperation;

static DazeCommandResult run_unicorn_prepared_callback(void *context) {
  const DazeUnicornPreparedOperation *operation = context;
  if (operation == NULL) return (DazeCommandResult){.disposition = DAZE_COMMAND_POSTSTART_FAILED};
  return daze_unicorn_run_prepared(operation->launch, operation->unicorn_context, operation->path);
}
#endif

DazeCommandResult run_selected_prepared(DazePreparedLaunch *launch, void *unicorn_context,
                                        const char *path, DazeBackendRequest requested,
                                        const DazeBackendSelection *selection,
                                        const DazeKvmCandidateObservation *candidate,
                                        DazeKvmMachine *machine,
                                        DazeKvmSelectionDiagnostic *diagnostic,
                                        DazeKvmNormalOperationObservation *observation) {
  if (selection == NULL || candidate == NULL || diagnostic == NULL)
    return (DazeCommandResult){.disposition = DAZE_COMMAND_POSTSTART_FAILED};
  if (selection->action == DAZE_BACKEND_SELECTION_FAIL) {
    *diagnostic = daze_kvm_selection_diagnostic_build(
      requested, selection, candidate,
      &(DazeKvmSelectedOperationResult){.command = {.disposition = DAZE_COMMAND_POSTSTART_FAILED}});
    return (DazeCommandResult){.disposition = DAZE_COMMAND_PRESTART_REJECTED};
  }
#if DAZE_HAS_UNICORN
  DazeUnicornPreparedOperation unicorn = {
    .launch = launch, .unicorn_context = unicorn_context, .path = path};
  const DazeKvmSelectedOperationUnicornRun run_unicorn = run_unicorn_prepared_callback;
  void *unicorn_operation_context = &unicorn;
#else
  const DazeKvmSelectedOperationUnicornRun run_unicorn = NULL;
  void *unicorn_operation_context = NULL;
  (void)unicorn_context;
  (void)path;
#endif
  const DazeKvmSelectedOperationResult operation = daze_kvm_selected_operation_run_record(
    &(DazeKvmSelectedOperationInput){.selection = *selection,
                                     .kvm_request = launch->kvm_request,
                                     .kvm_machine = machine,
                                     .run_unicorn = run_unicorn,
                                     .unicorn_context = unicorn_operation_context,
                                     .kvm_observation = observation});
  *diagnostic = daze_kvm_selection_diagnostic_build(requested, selection, candidate, &operation);
  return operation.command;
}

void report_kvm_terminal_observation(int debug, const DazeKvmSelectionDiagnostic *diagnostic,
                                     const DazeKvmNormalOperationObservation *observation) {
  if (diagnostic == NULL || observation == NULL || !debug ||
      diagnostic->kind != DAZE_KVM_SELECTION_DIAGNOSTIC_POSTSTART_FAILURE)
    return;
  fprintf(
    stderr,
    "kvm: terminal present=%d source=%d capture=%d owner=%d exit=%d raw=%" PRIu32
    " cs:ip=%04x:%08" PRIx32 " ax=%04x bx=%04x cx=%04x dx=%04x ds=%04x es=%04x ss:sp=%04x:%04x"
    " request=%02x/%04x/%04x/%04x/%04x/%04x"
    " pio=%04x:%u:%u:%u bases=%08x/%08x/%08x gdt=%08x idt=%08x"
    " stage=%d/%d"
    " gate=%d"
    " mediator=%d:%02x/%04x/%08x"
    " runner=%d/%02x/%04x/%04x/%04x/%04x/%04x/%04x/%04x/%04x\n",
    observation->present, observation->source, observation->capture_status,
    observation->owner_disposition, observation->exit_kind, observation->raw_exit_reason,
    observation->cs, observation->rip, observation->ax, observation->bx, observation->cx,
    observation->dx, observation->ds, observation->es, observation->ss, observation->sp,
    observation->request_vector, observation->request_ax, observation->request_bx,
    observation->request_cx, observation->request_dx, observation->request_ds,
    observation->pio_port, observation->pio_direction, observation->pio_size,
    observation->pio_value, observation->cs_base, observation->ss_base, observation->es_base,
    observation->gdt_base, observation->idt_base, observation->transition_stage,
    observation->transition_status, observation->post_return_gate_status,
    observation->post_return_request_present, observation->post_return_function,
    observation->post_return_selector, observation->post_return_operand,
    observation->runner_request_present, observation->runner_vector, observation->runner_ax,
    observation->runner_bx, observation->runner_cx, observation->runner_dx, observation->runner_ds,
    observation->runner_es, observation->runner_si, observation->runner_di);
}

/* Forced Unicorn and unavailable builds must not initialize KVM. */
DazeKvmCandidateObservation select_prepared_backend(const DazePreparedLaunch *launch,
                                                    DazeBackendRequest requested,
                                                    DazeBackendCompileAvailability compiled,
                                                    DazeKvmMachine *machine) {
  const DazeKvmMachineInitResult unavailable = {
    .status = DAZE_KVM_MACHINE_UNAVAILABLE, .stage = DAZE_KVM_MACHINE_STAGE_OPEN, .error = ENOENT};
  if (machine == NULL) return daze_kvm_candidate_observation_from_init(NULL);
  *machine = (DazeKvmMachine){.kvm = -1, .vm = -1, .vcpu = -1};
  if (requested == DAZE_BACKEND_REQUEST_UNICORN || !compiled.kvm_compiled || launch == NULL ||
      launch->kvm_request == NULL)
    return daze_kvm_candidate_observation_from_init(&unavailable);
  DazeKvmCandidateObservation observation;
  if (!daze_kvm_candidate_prepare(launch->kvm_request->guest_size, machine, &observation))
    return daze_kvm_candidate_observation_from_init(NULL);
  return observation;
}

/* Unicorn is required by the build; KVM availability is compile-time optional. */
DazeBackendCompileAvailability backend_compile_availability(void) {
  return (DazeBackendCompileAvailability){.kvm_compiled = daze_kvm_machine_compiled(),
                                          .unicorn_compiled = DAZE_HAS_UNICORN};
}

void report_selection_failure(const char *path, const DazeBackendSelection *selection) {
  switch (selection->diagnostic) {
  case DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED:
    fprintf(stderr, "daze: KVM backend was not compiled into this build\n");
    break;
  case DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED:
    fprintf(stderr, "daze: Unicorn backend was not compiled into this build\n");
    break;
  case DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE:
    fprintf(stderr, "daze: no usable backend remains\n");
    break;
  case DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE:
    fprintf(stderr, "daze: KVM backend is unavailable on this host\n");
    break;
  case DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED:
  case DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID:
    fprintf(stderr, "daze: KVM initialization failed\n");
    break;
  case DAZE_BACKEND_DIAGNOSTIC_KVM_POSTSTART_FAILURE:
  case DAZE_BACKEND_DIAGNOSTIC_NONE:
  default:
    break;
  }
  (void)path;
}

void report_selection_fallback(const DazeKvmSelectionDiagnostic *diagnostic, int unicorn_compiled) {
  if (diagnostic == NULL) return;
  if (!unicorn_compiled) {
    if (diagnostic->kind == DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE &&
        diagnostic->kvm_prestart_rejected)
      fprintf(stderr,
              "daze: KVM rejected before guest execution; Unicorn fallback is not compiled in\n");
    return;
  }
  switch (diagnostic->kind) {
  case DAZE_KVM_SELECTION_DIAGNOSTIC_UNAVAILABLE:
    fprintf(stderr, "daze: KVM unavailable; falling back to Unicorn\n");
    break;
  case DAZE_KVM_SELECTION_DIAGNOSTIC_REJECTED:
  case DAZE_KVM_SELECTION_DIAGNOSTIC_PRESTART_FALLBACK:
    fprintf(stderr, "daze: KVM initialization failed; falling back to Unicorn\n");
    break;
  default:
    break;
  }
}

void report_kvm_selection_diagnostic(int debug, const DazeKvmSelectionDiagnostic *diagnostic) {
  if (diagnostic == NULL || !debug) return;
  fprintf(stderr,
          "kvm: category=%d setup=%d backend=%d command=%d attempted=%d prestart=%d started=%d "
          "exit=%u requested=%d\n",
          diagnostic->kind, diagnostic->setup_reason, diagnostic->backend_diagnostic,
          diagnostic->command_disposition, diagnostic->kvm_attempted,
          diagnostic->kvm_prestart_rejected, diagnostic->guest_execution_started,
          diagnostic->dos_exit_code, diagnostic->requested);
}

void report_kvm_selection_metrics(int metrics_enabled, const DazeRunMetrics *run_metrics,
                                  const DazeKvmSelectionDiagnostic *diagnostic) {
  if (run_metrics == NULL || diagnostic == NULL || !metrics_enabled) return;
  const DazeKvmSelectionMetrics metrics = daze_kvm_selection_metrics_from_diagnostic(diagnostic);
  fprintf(stderr, "metrics: backend=%s selection=%s\n", metrics.backend, metrics.selection);
  daze_metrics_report_run(run_metrics);
}
