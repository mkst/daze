#include "backend_selection.h"

static int expect_request(DazeBackendRequest requested, DazeBackendCompileAvailability compiled,
                          DazeKvmCandidateOutcome outcome, DazeBackendSelectionAction action,
                          DazeBackendDiagnostic diagnostic) {
  const DazeBackendSelection selection =
    daze_backend_selection_decide_request(requested, compiled, outcome);
  return selection.action == action && selection.diagnostic == diagnostic;
}

int main(void) {
  const DazeBackendCompileAvailability both = {.kvm_compiled = 1, .unicorn_compiled = 1};
  const DazeBackendCompileAvailability kvm_only = {.kvm_compiled = 1, .unicorn_compiled = 0};
  const DazeBackendCompileAvailability unicorn_only = {.kvm_compiled = 0, .unicorn_compiled = 1};
  const DazeBackendCompileAvailability none = {.kvm_compiled = 0, .unicorn_compiled = 0};
  return /* auto: KVM -> Unicorn -> failure, only when compiled in. */
    expect_request(DAZE_BACKEND_REQUEST_AUTO, both, DAZE_KVM_CANDIDATE_USABLE,
                   DAZE_BACKEND_SELECTION_USE_KVM, DAZE_BACKEND_DIAGNOSTIC_NONE) &&
        expect_request(DAZE_BACKEND_REQUEST_AUTO, both, DAZE_KVM_CANDIDATE_UNAVAILABLE,
                       DAZE_BACKEND_SELECTION_USE_UNICORN,
                       DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE) &&
        expect_request(DAZE_BACKEND_REQUEST_AUTO, both, DAZE_KVM_CANDIDATE_REJECTED,
                       DAZE_BACKEND_SELECTION_USE_UNICORN, DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED) &&
        expect_request(DAZE_BACKEND_REQUEST_AUTO, both, DAZE_KVM_CANDIDATE_INVALID,
                       DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID) &&
        expect_request(DAZE_BACKEND_REQUEST_AUTO, unicorn_only, DAZE_KVM_CANDIDATE_USABLE,
                       DAZE_BACKEND_SELECTION_USE_UNICORN,
                       DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED) &&
        expect_request(DAZE_BACKEND_REQUEST_AUTO, none, DAZE_KVM_CANDIDATE_USABLE,
                       DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE) &&
        expect_request(DAZE_BACKEND_REQUEST_AUTO, kvm_only, DAZE_KVM_CANDIDATE_UNAVAILABLE,
                       DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE) &&
        expect_request(DAZE_BACKEND_REQUEST_AUTO, kvm_only, DAZE_KVM_CANDIDATE_REJECTED,
                       DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED) &&
        /* kvm: usable, else terminal FAIL, never Unicorn. */
        expect_request(DAZE_BACKEND_REQUEST_KVM, both, DAZE_KVM_CANDIDATE_USABLE,
                       DAZE_BACKEND_SELECTION_USE_KVM_STRICT, DAZE_BACKEND_DIAGNOSTIC_NONE) &&
        expect_request(DAZE_BACKEND_REQUEST_KVM, both, DAZE_KVM_CANDIDATE_UNAVAILABLE,
                       DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_UNAVAILABLE) &&
        expect_request(DAZE_BACKEND_REQUEST_KVM, both, DAZE_KVM_CANDIDATE_REJECTED,
                       DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED) &&
        expect_request(DAZE_BACKEND_REQUEST_KVM, both, DAZE_KVM_CANDIDATE_INVALID,
                       DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_INVALID) &&
        expect_request(DAZE_BACKEND_REQUEST_KVM, unicorn_only, DAZE_KVM_CANDIDATE_USABLE,
                       DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_KVM_NOT_COMPILED) &&
        expect_request(DAZE_BACKEND_REQUEST_UNICORN, both, DAZE_KVM_CANDIDATE_USABLE,
                       DAZE_BACKEND_SELECTION_USE_UNICORN, DAZE_BACKEND_DIAGNOSTIC_NONE) &&
        expect_request(DAZE_BACKEND_REQUEST_UNICORN, unicorn_only, DAZE_KVM_CANDIDATE_REJECTED,
                       DAZE_BACKEND_SELECTION_USE_UNICORN, DAZE_BACKEND_DIAGNOSTIC_NONE) &&
        expect_request(DAZE_BACKEND_REQUEST_UNICORN, kvm_only, DAZE_KVM_CANDIDATE_USABLE,
                       DAZE_BACKEND_SELECTION_FAIL, DAZE_BACKEND_DIAGNOSTIC_UNICORN_NOT_COMPILED) &&
        expect_request((DazeBackendRequest)99, both, DAZE_KVM_CANDIDATE_USABLE,
                       DAZE_BACKEND_SELECTION_USE_KVM, DAZE_BACKEND_DIAGNOSTIC_NONE)
      ? 0
      : 1;
}
