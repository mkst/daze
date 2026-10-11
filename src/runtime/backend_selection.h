#ifndef DAZE_BACKEND_SELECTION_H
#define DAZE_BACKEND_SELECTION_H

/* Selection consumes backend availability facts without probing or executing. */
typedef enum {
  DAZE_KVM_CANDIDATE_USABLE,
  DAZE_KVM_CANDIDATE_UNAVAILABLE,
  DAZE_KVM_CANDIDATE_REJECTED,
  DAZE_KVM_CANDIDATE_INVALID,
} DazeKvmCandidateOutcome;

/* Explicit backend requests never fall back. */
typedef enum {
  DAZE_BACKEND_REQUEST_AUTO,
  DAZE_BACKEND_REQUEST_KVM,
  DAZE_BACKEND_REQUEST_UNICORN,
} DazeBackendRequest;

typedef enum {
  DAZE_BACKEND_SELECTION_USE_UNICORN,
  DAZE_BACKEND_SELECTION_USE_KVM,
  DAZE_BACKEND_SELECTION_FAIL,
  /* Pre-start rejection is terminal for forced KVM. */
  DAZE_BACKEND_SELECTION_USE_KVM_STRICT,
} DazeBackendSelectionAction;

typedef enum {
  DAZE_BACKEND_DIAGNOSTIC_NONE,
  DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE,
  DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED,
  DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID,
  DAZE_BACKEND_DIAGNOSTIC_KVM_POSTSTART_FAILURE,
  DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED,
  DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED,
  DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE,
} DazeBackendDiagnostic;

typedef struct {
  DazeBackendSelectionAction action;
  DazeBackendDiagnostic diagnostic;
} DazeBackendSelection;

/* AUTO may select only compiled-in backends. */
typedef struct {
  int kvm_compiled;
  int unicorn_compiled;
} DazeBackendCompileAvailability;

/* AUTO prefers usable KVM; explicit KVM failures are terminal and forced Unicorn never
 * probes KVM. */
DazeBackendSelection daze_backend_selection_decide_request(DazeBackendRequest requested,
                                                           DazeBackendCompileAvailability compiled,
                                                           DazeKvmCandidateOutcome kvm_outcome);

#endif
