#include "selection_metrics.h"

#include <stdio.h>
#include <string.h>

static int expect(DazeKvmSelectionDiagnosticKind kind, const char *backend, const char *selection) {
  const DazeKvmSelectionMetrics metrics = daze_kvm_selection_metrics_from_diagnostic(
    &(DazeKvmSelectionDiagnostic){.kind = kind, .requested = DAZE_BACKEND_REQUEST_AUTO});
  return strcmp(metrics.backend, backend) == 0 && strcmp(metrics.selection, selection) == 0;
}

static int expect_requested(DazeKvmSelectionDiagnosticKind kind, DazeBackendRequest requested,
                            const char *backend, const char *selection) {
  const DazeKvmSelectionMetrics metrics = daze_kvm_selection_metrics_from_diagnostic(
    &(DazeKvmSelectionDiagnostic){.kind = kind, .requested = requested});
  return strcmp(metrics.backend, backend) == 0 && strcmp(metrics.selection, selection) == 0;
}

int main(void) {
  return !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_UNAVAILABLE, "unicorn", "kvm-unavailable") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_REJECTED, "unicorn", "kvm-rejected") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_INVALID, "none", "kvm-invalid") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_PRESTART_FALLBACK, "unicorn",
                     "kvm-prestart-rejected") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_COMPLETED, "kvm", "kvm-completed") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_POSTSTART_FAILURE, "kvm",
                     "kvm-poststart-failure") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_REQUESTED, "unicorn", "unicorn") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_REQUESTED_FAILURE, "none",
                     "kvm-requested-failure") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_NOT_COMPILED, "unicorn",
                     "kvm-not-compiled") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_NOT_COMPILED, "none",
                     "unicorn-not-compiled") ||
             !expect(DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE, "none",
                     "no-backend-available") ||
             !expect_requested(DAZE_KVM_SELECTION_DIAGNOSTIC_UNAVAILABLE, DAZE_BACKEND_REQUEST_KVM,
                               "none", "kvm-unavailable") ||
             !expect_requested(DAZE_KVM_SELECTION_DIAGNOSTIC_REJECTED, DAZE_BACKEND_REQUEST_KVM,
                               "none", "kvm-rejected") ||
             !expect_requested(DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_NOT_COMPILED,
                               DAZE_BACKEND_REQUEST_KVM, "none", "kvm-not-compiled") ||
             !expect_requested(DAZE_KVM_SELECTION_DIAGNOSTIC_COMPLETED, DAZE_BACKEND_REQUEST_KVM,
                               "kvm", "kvm-completed") ||
             strcmp(daze_kvm_selection_metrics_from_diagnostic(NULL).backend, "none") != 0
           ? 1
           : 0;
}
