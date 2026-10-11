#include "selection.h"

static DazeKvmSelectionDiagnostic invalid(void) {
  return (DazeKvmSelectionDiagnostic){
    .kind = DAZE_KVM_SELECTION_DIAGNOSTIC_INVALID,
    .setup_reason = DAZE_KVM_SETUP_REASON_INVALID,
    .backend_diagnostic = DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID,
    .command_disposition = DAZE_COMMAND_POSTSTART_FAILED,
  };
}

DazeKvmSelectionDiagnostic daze_kvm_selection_diagnostic_build(
  DazeBackendRequest requested, const DazeBackendSelection *selection,
  const DazeKvmCandidateObservation *candidate, const DazeKvmSelectedOperationResult *operation) {
  if (selection == NULL || candidate == NULL || operation == NULL) return invalid();
  DazeKvmSelectionDiagnostic diagnostic = {
    .requested = requested,
    .setup_reason = candidate->reason,
    .backend_diagnostic = selection->diagnostic,
    .command_disposition = operation->command.disposition,
    .dos_exit_code = operation->command.dos_exit_code,
    .guest_execution_started = operation->command.guest_execution_started,
    .kvm_attempted = operation->kvm_attempted,
    .kvm_prestart_rejected = operation->kvm_prestart_rejected,
  };
  if (requested == DAZE_BACKEND_REQUEST_UNICORN) {
    if (selection->action == DAZE_BACKEND_SELECTION_FAIL &&
        selection->diagnostic == DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED) {
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_NOT_COMPILED;
      diagnostic.setup_reason = DAZE_KVM_SETUP_REASON_NONE;
      return diagnostic;
    }
    diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_REQUESTED;
    diagnostic.setup_reason = DAZE_KVM_SETUP_REASON_NONE;
    diagnostic.backend_diagnostic = DAZE_BACKEND_DIAGNOSTIC_NONE;
    return diagnostic;
  }
  switch (selection->action) {
  case DAZE_BACKEND_SELECTION_USE_UNICORN:
    switch (selection->diagnostic) {
    case DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE:
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_UNAVAILABLE;
      break;
    case DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED:
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_REJECTED;
      break;
    case DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED:
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_NOT_COMPILED;
      diagnostic.setup_reason = DAZE_KVM_SETUP_REASON_NONE;
      break;
    default:
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_INVALID;
      break;
    }
    return diagnostic;
  case DAZE_BACKEND_SELECTION_USE_KVM:
  case DAZE_BACKEND_SELECTION_USE_KVM_STRICT:
    if (operation->kvm_prestart_rejected) {
      if (requested == DAZE_BACKEND_REQUEST_KVM) {
        diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_REQUESTED_FAILURE;
      } else if (!operation->unicorn_attempted) {
        diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE;
        diagnostic.backend_diagnostic = DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE;
      } else {
        diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_PRESTART_FALLBACK;
      }
    } else if (operation->command.disposition == DAZE_COMMAND_COMPLETED) {
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_COMPLETED;
    } else {
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_POSTSTART_FAILURE;
    }
    return diagnostic;
  case DAZE_BACKEND_SELECTION_FAIL:
    switch (selection->diagnostic) {
    case DAZE_BACKEND_DIAGNOSTIC_KVM_POSTSTART_FAILURE:
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_POSTSTART_FAILURE;
      break;
    case DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED:
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_NOT_COMPILED;
      diagnostic.setup_reason = DAZE_KVM_SETUP_REASON_NONE;
      break;
    case DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED:
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_NOT_COMPILED;
      diagnostic.setup_reason = DAZE_KVM_SETUP_REASON_NONE;
      break;
    case DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE:
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE;
      diagnostic.setup_reason = DAZE_KVM_SETUP_REASON_NONE;
      break;
    case DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE:
    case DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED:
      diagnostic.kind = requested == DAZE_BACKEND_REQUEST_KVM
                          ? DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_REQUESTED_FAILURE
                          : DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE;
      break;
    case DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID:
    default:
      diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_INVALID;
      break;
    }
    return diagnostic;
  default:
    return invalid();
  }
}
