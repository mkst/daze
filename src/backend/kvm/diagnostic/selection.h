#ifndef DAZE_KVM_SELECTION_DIAGNOSTIC_H
#define DAZE_KVM_SELECTION_DIAGNOSTIC_H

#include "candidate_observation.h"
#include "selected_operation.h"

/* Stable host-facing diagnostic categories, independent of host errno text. */
typedef enum {
  DAZE_KVM_SELECTION_DIAGNOSTIC_UNAVAILABLE,
  DAZE_KVM_SELECTION_DIAGNOSTIC_REJECTED,
  DAZE_KVM_SELECTION_DIAGNOSTIC_INVALID,
  DAZE_KVM_SELECTION_DIAGNOSTIC_PRESTART_FALLBACK,
  DAZE_KVM_SELECTION_DIAGNOSTIC_COMPLETED,
  DAZE_KVM_SELECTION_DIAGNOSTIC_POSTSTART_FAILURE,
  DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_REQUESTED,
  DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_REQUESTED_FAILURE,
  DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_NOT_COMPILED,
  DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_NOT_COMPILED,
  DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE,
} DazeKvmSelectionDiagnosticKind;

typedef struct {
  DazeKvmSelectionDiagnosticKind kind;
  DazeBackendRequest requested;
  DazeKvmSetupReason setup_reason;
  DazeBackendDiagnostic backend_diagnostic;
  DazeCommandDisposition command_disposition;
  uint8_t dos_exit_code;
  int guest_execution_started;
  int kvm_attempted;
  int kvm_prestart_rejected;
} DazeKvmSelectionDiagnostic;

/* Forced KVM setup rejection is terminal, not a fallback request. */
DazeKvmSelectionDiagnostic daze_kvm_selection_diagnostic_build(
  DazeBackendRequest requested, const DazeBackendSelection *selection,
  const DazeKvmCandidateObservation *candidate, const DazeKvmSelectedOperationResult *operation);

#endif
