#include "selected_operation.h"

static DazeCommandResult terminal_failure(int guest_execution_started) {
  return (DazeCommandResult){.disposition = DAZE_COMMAND_POSTSTART_FAILED,
                             .guest_execution_started = guest_execution_started != 0};
}

static DazeCommandResult run_unicorn(DazeKvmSelectedOperationUnicornRun operation, void *context) {
  return operation == NULL ? terminal_failure(0) : operation(context);
}

DazeCommandResult daze_kvm_selected_operation_resolve(const DazeBackendSelection *selection,
                                                      DazeKvmSelectedOperationUnicornRun operation,
                                                      void *context, DazeCommandResult kvm_result) {
  if (selection == NULL) return terminal_failure(0);
  switch (selection->action) {
  case DAZE_BACKEND_SELECTION_USE_UNICORN:
    return run_unicorn(operation, context);
  case DAZE_BACKEND_SELECTION_USE_KVM:
    return kvm_result.disposition == DAZE_COMMAND_PRESTART_REJECTED
             ? run_unicorn(operation, context)
             : kvm_result;
  case DAZE_BACKEND_SELECTION_USE_KVM_STRICT:
    return kvm_result;
  case DAZE_BACKEND_SELECTION_FAIL:
  default:
    return terminal_failure(selection->diagnostic == DAZE_BACKEND_DIAGNOSTIC_KVM_POSTSTART_FAILURE);
  }
}

DazeKvmSelectedOperationResult
daze_kvm_selected_operation_run_record(const DazeKvmSelectedOperationInput *input) {
  if (input == NULL) return (DazeKvmSelectedOperationResult){.command = terminal_failure(0)};
  DazeCommandResult kvm = {.disposition = DAZE_COMMAND_POSTSTART_FAILED};
  const int kvm_attempted = input->selection.action == DAZE_BACKEND_SELECTION_USE_KVM ||
                            input->selection.action == DAZE_BACKEND_SELECTION_USE_KVM_STRICT;
  if (kvm_attempted)
    kvm = daze_kvm_normal_operation_run_observe(input->kvm_request, input->kvm_machine,
                                                input->kvm_observation);
  const int unicorn_attempted =
    input->run_unicorn != NULL && (input->selection.action == DAZE_BACKEND_SELECTION_USE_UNICORN ||
                                   (input->selection.action == DAZE_BACKEND_SELECTION_USE_KVM &&
                                    kvm.disposition == DAZE_COMMAND_PRESTART_REJECTED));
  return (DazeKvmSelectedOperationResult){
    .command = daze_kvm_selected_operation_resolve(&input->selection, input->run_unicorn,
                                                   input->unicorn_context, kvm),
    .kvm_attempted = kvm_attempted,
    .kvm_prestart_rejected = kvm_attempted && kvm.disposition == DAZE_COMMAND_PRESTART_REJECTED,
    .unicorn_attempted = unicorn_attempted,
  };
}
