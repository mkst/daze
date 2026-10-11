#include "selection.h"

static DazeKvmCandidateObservation candidate(DazeKvmCandidateOutcome outcome,
                                             DazeKvmSetupReason reason) {
  return (DazeKvmCandidateObservation){.outcome = outcome, .reason = reason};
}

static DazeBackendSelection selection(DazeBackendSelectionAction action,
                                      DazeBackendDiagnostic backend) {
  return (DazeBackendSelection){.action = action, .diagnostic = backend};
}

static DazeKvmSelectedOperationResult operation(DazeCommandDisposition disposition, int started,
                                                int attempted, int prestart) {
  return (DazeKvmSelectedOperationResult){
    .command = {.disposition = disposition, .dos_exit_code = 9, .guest_execution_started = started},
    .kvm_attempted = attempted,
    .kvm_prestart_rejected = prestart,
    .unicorn_attempted = prestart && (started || disposition == DAZE_COMMAND_COMPLETED)};
}

static int expect(DazeBackendRequest requested, DazeBackendSelection selection_input,
                  DazeKvmCandidateObservation candidate_input,
                  DazeKvmSelectedOperationResult operation_input,
                  DazeKvmSelectionDiagnosticKind kind, DazeKvmSetupReason reason,
                  DazeBackendDiagnostic backend) {
  const DazeKvmSelectionDiagnostic diagnostic = daze_kvm_selection_diagnostic_build(
    requested, &selection_input, &candidate_input, &operation_input);
  return diagnostic.kind == kind && diagnostic.requested == requested &&
         diagnostic.setup_reason == reason && diagnostic.backend_diagnostic == backend &&
         diagnostic.command_disposition == operation_input.command.disposition &&
         diagnostic.dos_exit_code == operation_input.command.dos_exit_code &&
         diagnostic.guest_execution_started == operation_input.command.guest_execution_started &&
         diagnostic.kvm_attempted == operation_input.kvm_attempted &&
         diagnostic.kvm_prestart_rejected == operation_input.kvm_prestart_rejected;
}

int main(void) {
  const DazeBackendRequest auto_request = DAZE_BACKEND_REQUEST_AUTO;
  const DazeBackendRequest kvm_request = DAZE_BACKEND_REQUEST_KVM;
  const DazeKvmSelectedOperationResult unicorn = operation(DAZE_COMMAND_COMPLETED, 1, 0, 0);
  return expect(
           auto_request,
           selection(DAZE_BACKEND_SELECTION_USE_UNICORN, DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE),
           candidate(DAZE_KVM_CANDIDATE_UNAVAILABLE, DAZE_KVM_SETUP_REASON_NO_DEVICE), unicorn,
           DAZE_KVM_SELECTION_DIAGNOSTIC_UNAVAILABLE, DAZE_KVM_SETUP_REASON_NO_DEVICE,
           DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE) &&
             expect(
               auto_request,
               selection(DAZE_BACKEND_SELECTION_USE_UNICORN, DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED),
               candidate(DAZE_KVM_CANDIDATE_REJECTED, DAZE_KVM_SETUP_REASON_VM_CREATION), unicorn,
               DAZE_KVM_SELECTION_DIAGNOSTIC_REJECTED, DAZE_KVM_SETUP_REASON_VM_CREATION,
               DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED) &&
             expect(
               auto_request,
               selection(DAZE_BACKEND_SELECTION_USE_UNICORN, DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID),
               candidate(DAZE_KVM_CANDIDATE_INVALID, DAZE_KVM_SETUP_REASON_INVALID), unicorn,
               DAZE_KVM_SELECTION_DIAGNOSTIC_INVALID, DAZE_KVM_SETUP_REASON_INVALID,
               DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID) &&
             expect(auto_request,
                    selection(DAZE_BACKEND_SELECTION_USE_KVM, DAZE_BACKEND_DIAGNOSTIC_NONE),
                    candidate(DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NONE),
                    operation(DAZE_COMMAND_COMPLETED, 1, 1, 1),
                    DAZE_KVM_SELECTION_DIAGNOSTIC_PRESTART_FALLBACK, DAZE_KVM_SETUP_REASON_NONE,
                    DAZE_BACKEND_DIAGNOSTIC_NONE) &&
             expect(auto_request,
                    selection(DAZE_BACKEND_SELECTION_USE_KVM, DAZE_BACKEND_DIAGNOSTIC_NONE),
                    candidate(DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NONE),
                    operation(DAZE_COMMAND_POSTSTART_FAILED, 0, 1, 1),
                    DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE, DAZE_KVM_SETUP_REASON_NONE,
                    DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE) &&
             expect(auto_request,
                    selection(DAZE_BACKEND_SELECTION_USE_KVM, DAZE_BACKEND_DIAGNOSTIC_NONE),
                    candidate(DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NONE),
                    operation(DAZE_COMMAND_COMPLETED, 1, 1, 0),
                    DAZE_KVM_SELECTION_DIAGNOSTIC_COMPLETED, DAZE_KVM_SETUP_REASON_NONE,
                    DAZE_BACKEND_DIAGNOSTIC_NONE) &&
             expect(auto_request,
                    selection(DAZE_BACKEND_SELECTION_USE_KVM, DAZE_BACKEND_DIAGNOSTIC_NONE),
                    candidate(DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NONE),
                    operation(DAZE_COMMAND_POSTSTART_FAILED, 1, 1, 0),
                    DAZE_KVM_SELECTION_DIAGNOSTIC_POSTSTART_FAILURE, DAZE_KVM_SETUP_REASON_NONE,
                    DAZE_BACKEND_DIAGNOSTIC_NONE) &&
             /* forced unicorn never probes: ignored candidate, NONE facts. */
             expect(
               DAZE_BACKEND_REQUEST_UNICORN,
               selection(DAZE_BACKEND_SELECTION_USE_UNICORN, DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED),
               candidate(DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NO_DEVICE), unicorn,
               DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_REQUESTED, DAZE_KVM_SETUP_REASON_NONE,
               DAZE_BACKEND_DIAGNOSTIC_NONE) &&
             /* forced KVM pre-start rejection is a terminal KVM failure. */
             expect(kvm_request,
                    selection(DAZE_BACKEND_SELECTION_USE_KVM_STRICT, DAZE_BACKEND_DIAGNOSTIC_NONE),
                    candidate(DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NONE),
                    operation(DAZE_COMMAND_PRESTART_REJECTED, 0, 1, 1),
                    DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_REQUESTED_FAILURE, DAZE_KVM_SETUP_REASON_NONE,
                    DAZE_BACKEND_DIAGNOSTIC_NONE) &&
             /* forced KVM unavailable is a terminal KVM failure. */
             expect(kvm_request,
                    selection(DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE),
                    candidate(DAZE_KVM_CANDIDATE_UNAVAILABLE, DAZE_KVM_SETUP_REASON_NO_DEVICE),
                    unicorn, DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_REQUESTED_FAILURE,
                    DAZE_KVM_SETUP_REASON_NO_DEVICE, DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE) &&
             /* auto with no Unicorn fallback compiled is no-backend. */
             expect(auto_request,
                    selection(DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE),
                    candidate(DAZE_KVM_CANDIDATE_UNAVAILABLE, DAZE_KVM_SETUP_REASON_NO_DEVICE),
                    unicorn, DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE,
                    DAZE_KVM_SETUP_REASON_NO_DEVICE, DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE) &&
             /* not compiled requests are not runtime probe results. */
             expect(auto_request,
                    selection(DAZE_BACKEND_SELECTION_USE_UNICORN,
                              DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED),
                    candidate(DAZE_KVM_CANDIDATE_UNAVAILABLE, DAZE_KVM_SETUP_REASON_NO_DEVICE),
                    unicorn, DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_NOT_COMPILED,
                    DAZE_KVM_SETUP_REASON_NONE, DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED) &&
             expect(
               kvm_request,
               selection(DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED),
               candidate(DAZE_KVM_CANDIDATE_UNAVAILABLE, DAZE_KVM_SETUP_REASON_NO_DEVICE), unicorn,
               DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_NOT_COMPILED, DAZE_KVM_SETUP_REASON_NONE,
               DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED) &&
             expect(
               auto_request,
               selection(DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED),
               candidate(DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NONE), unicorn,
               DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_NOT_COMPILED, DAZE_KVM_SETUP_REASON_NONE,
               DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED) &&
             expect(
               DAZE_BACKEND_REQUEST_UNICORN,
               selection(DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED),
               candidate(DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NONE), unicorn,
               DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_NOT_COMPILED, DAZE_KVM_SETUP_REASON_NONE,
               DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED) &&
             expect(
               auto_request,
               selection(DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE),
               candidate(DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NONE), unicorn,
               DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE, DAZE_KVM_SETUP_REASON_NONE,
               DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE) &&
             daze_kvm_selection_diagnostic_build(auto_request, NULL, NULL, NULL).kind ==
               DAZE_KVM_SELECTION_DIAGNOSTIC_INVALID
           ? 0
           : 1;
}
