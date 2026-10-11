#include "backend_selection.h"

DazeBackendSelection daze_backend_selection_decide_request(DazeBackendRequest requested,
                                                           DazeBackendCompileAvailability compiled,
                                                           DazeKvmCandidateOutcome kvm_outcome) {
  switch (requested) {
  case DAZE_BACKEND_REQUEST_UNICORN:
    return compiled.unicorn_compiled
             ? (DazeBackendSelection){DAZE_BACKEND_SELECTION_USE_UNICORN,
                                      DAZE_BACKEND_DIAGNOSTIC_NONE}
             : (DazeBackendSelection){DAZE_BACKEND_SELECTION_FAIL,
                                      DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED};
  case DAZE_BACKEND_REQUEST_KVM:
    if (!compiled.kvm_compiled)
      return (DazeBackendSelection){DAZE_BACKEND_SELECTION_FAIL,
                                    DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED};
    switch (kvm_outcome) {
    case DAZE_KVM_CANDIDATE_USABLE:
      return (DazeBackendSelection){DAZE_BACKEND_SELECTION_USE_KVM_STRICT,
                                    DAZE_BACKEND_DIAGNOSTIC_NONE};
    case DAZE_KVM_CANDIDATE_UNAVAILABLE:
      return (DazeBackendSelection){DAZE_BACKEND_SELECTION_FAIL,
                                    DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE};
    case DAZE_KVM_CANDIDATE_REJECTED:
      return (DazeBackendSelection){DAZE_BACKEND_SELECTION_FAIL,
                                    DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED};
    case DAZE_KVM_CANDIDATE_INVALID:
    default:
      return (DazeBackendSelection){DAZE_BACKEND_SELECTION_FAIL,
                                    DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID};
    }
  case DAZE_BACKEND_REQUEST_AUTO:
  default:
    if (!compiled.kvm_compiled)
      return compiled.unicorn_compiled
               ? (DazeBackendSelection){DAZE_BACKEND_SELECTION_USE_UNICORN,
                                        DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED}
               : (DazeBackendSelection){DAZE_BACKEND_SELECTION_FAIL,
                                        DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE};
    switch (kvm_outcome) {
    case DAZE_KVM_CANDIDATE_USABLE:
      return (DazeBackendSelection){DAZE_BACKEND_SELECTION_USE_KVM, DAZE_BACKEND_DIAGNOSTIC_NONE};
    case DAZE_KVM_CANDIDATE_UNAVAILABLE:
      return compiled.unicorn_compiled
               ? (DazeBackendSelection){DAZE_BACKEND_SELECTION_USE_UNICORN,
                                        DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE}
               : (DazeBackendSelection){DAZE_BACKEND_SELECTION_FAIL,
                                        DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE};
    case DAZE_KVM_CANDIDATE_REJECTED:
      return compiled.unicorn_compiled
               ? (DazeBackendSelection){DAZE_BACKEND_SELECTION_USE_UNICORN,
                                        DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED}
               : (DazeBackendSelection){DAZE_BACKEND_SELECTION_FAIL,
                                        DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED};
    case DAZE_KVM_CANDIDATE_INVALID:
    default:
      return (DazeBackendSelection){DAZE_BACKEND_SELECTION_FAIL,
                                    DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID};
    }
  }
}
