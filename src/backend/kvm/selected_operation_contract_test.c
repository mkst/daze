#include "selected_operation.h"

typedef struct {
  int count;
} UnicornRun;

static DazeCommandResult unicorn_result(void *context) {
  UnicornRun *run = context;
  if (run != NULL) ++run->count;
  return (DazeCommandResult){
    .disposition = DAZE_COMMAND_COMPLETED, .dos_exit_code = 37, .guest_execution_started = 1};
}

int main(void) {
  UnicornRun run = {0};
  const DazeKvmSelectedOperationInput use_unicorn = {
    .selection = {DAZE_BACKEND_SELECTION_USE_UNICORN, DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE},
    .run_unicorn = unicorn_result,
    .unicorn_context = &run};
  if (daze_kvm_selected_operation_run_record(&use_unicorn).command.disposition !=
        DAZE_COMMAND_COMPLETED ||
      daze_kvm_selected_operation_run_record(&use_unicorn).command.dos_exit_code != 37 ||
      run.count != 2)
    return 1;
  const DazeKvmSelectedOperationInput rejected_kvm = {
    .selection = {DAZE_BACKEND_SELECTION_USE_KVM, DAZE_BACKEND_DIAGNOSTIC_NONE},
    .kvm_request = NULL,
    .run_unicorn = unicorn_result,
    .unicorn_context = &run};
  if (daze_kvm_selected_operation_run_record(&rejected_kvm).command.disposition !=
        DAZE_COMMAND_COMPLETED ||
      daze_kvm_selected_operation_run_record(&rejected_kvm).command.dos_exit_code != 37 ||
      run.count != 4)
    return 1;
  const DazeKvmSelectedOperationResult fallback =
    daze_kvm_selected_operation_run_record(&rejected_kvm);
  if (fallback.command.disposition != DAZE_COMMAND_COMPLETED || !fallback.kvm_attempted ||
      !fallback.kvm_prestart_rejected || !fallback.unicorn_attempted || run.count != 5)
    return 1;
  /* Forced KVM: a pre-start rejection is terminal and never invokes Unicorn. */
  const DazeKvmSelectedOperationInput strict_kvm = {
    .selection = {DAZE_BACKEND_SELECTION_USE_KVM_STRICT, DAZE_BACKEND_DIAGNOSTIC_NONE},
    .kvm_request = NULL,
    .run_unicorn = unicorn_result,
    .unicorn_context = &run};
  const DazeCommandResult strict = daze_kvm_selected_operation_run_record(&strict_kvm).command;
  if (strict.disposition != DAZE_COMMAND_PRESTART_REJECTED || run.count != 5) return 1;
  const DazeKvmSelectedOperationResult strict_record =
    daze_kvm_selected_operation_run_record(&strict_kvm);
  if (strict_record.command.disposition != DAZE_COMMAND_PRESTART_REJECTED ||
      !strict_record.kvm_attempted || !strict_record.kvm_prestart_rejected ||
      strict_record.unicorn_attempted || run.count != 5)
    return 1;
  const DazeKvmSelectedOperationInput no_fallback = {
    .selection = {DAZE_BACKEND_SELECTION_USE_KVM, DAZE_BACKEND_DIAGNOSTIC_NONE},
    .kvm_request = NULL};
  const DazeKvmSelectedOperationResult no_fallback_result =
    daze_kvm_selected_operation_run_record(&no_fallback);
  if (no_fallback_result.command.disposition != DAZE_COMMAND_POSTSTART_FAILED ||
      !no_fallback_result.kvm_prestart_rejected || no_fallback_result.unicorn_attempted)
    return 1;
  const DazeKvmSelectedOperationInput invalid = {
    .selection = {DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID},
    .run_unicorn = unicorn_result,
    .unicorn_context = &run};
  const DazeCommandResult invalid_result = daze_kvm_selected_operation_run_record(&invalid).command;
  if (invalid_result.disposition != DAZE_COMMAND_POSTSTART_FAILED ||
      invalid_result.guest_execution_started || run.count != 5)
    return 1;
  const DazeKvmSelectedOperationInput poststart = {
    .selection = {DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_POSTSTART_FAILURE},
    .run_unicorn = unicorn_result,
    .unicorn_context = &run};
  const DazeCommandResult poststart_result =
    daze_kvm_selected_operation_run_record(&poststart).command;
  if (poststart_result.disposition != DAZE_COMMAND_POSTSTART_FAILED ||
      !poststart_result.guest_execution_started ||
      daze_kvm_selected_operation_run_record(NULL).command.disposition !=
        DAZE_COMMAND_POSTSTART_FAILED ||
      run.count != 5)
    return 1;
  const DazeCommandResult kvm_poststart = {.disposition = DAZE_COMMAND_POSTSTART_FAILED,
                                           .guest_execution_started = 1};
  if (daze_kvm_selected_operation_resolve(&rejected_kvm.selection, unicorn_result, &run,
                                          kvm_poststart)
          .disposition != DAZE_COMMAND_POSTSTART_FAILED ||
      !daze_kvm_selected_operation_resolve(&rejected_kvm.selection, unicorn_result, &run,
                                           kvm_poststart)
         .guest_execution_started ||
      run.count != 5)
    return 1;
  return 0;
}
