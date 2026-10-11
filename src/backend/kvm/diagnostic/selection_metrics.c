#include "selection_metrics.h"

static DazeKvmSelectionMetrics unicorn_request(const char *selection) {
  return (DazeKvmSelectionMetrics){.backend = "unicorn", .selection = selection};
}

DazeKvmSelectionMetrics
daze_kvm_selection_metrics_from_diagnostic(const DazeKvmSelectionDiagnostic *diagnostic) {
  if (diagnostic == NULL)
    return (DazeKvmSelectionMetrics){.backend = "none", .selection = "kvm-invalid"};
  switch (diagnostic->kind) {
  case DAZE_KVM_SELECTION_DIAGNOSTIC_UNAVAILABLE:
    return diagnostic->requested == DAZE_BACKEND_REQUEST_KVM
             ? (DazeKvmSelectionMetrics){.backend = "none", .selection = "kvm-unavailable"}
             : unicorn_request("kvm-unavailable");
  case DAZE_KVM_SELECTION_DIAGNOSTIC_REJECTED:
    return diagnostic->requested == DAZE_BACKEND_REQUEST_KVM
             ? (DazeKvmSelectionMetrics){.backend = "none", .selection = "kvm-rejected"}
             : unicorn_request("kvm-rejected");
  case DAZE_KVM_SELECTION_DIAGNOSTIC_INVALID:
    return (DazeKvmSelectionMetrics){.backend = "none", .selection = "kvm-invalid"};
  case DAZE_KVM_SELECTION_DIAGNOSTIC_PRESTART_FALLBACK:
    return unicorn_request("kvm-prestart-rejected");
  case DAZE_KVM_SELECTION_DIAGNOSTIC_COMPLETED:
    return (DazeKvmSelectionMetrics){.backend = "kvm", .selection = "kvm-completed"};
  case DAZE_KVM_SELECTION_DIAGNOSTIC_POSTSTART_FAILURE:
    return (DazeKvmSelectionMetrics){.backend = "kvm", .selection = "kvm-poststart-failure"};
  case DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_REQUESTED:
    return unicorn_request("unicorn");
  case DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_REQUESTED_FAILURE:
    return (DazeKvmSelectionMetrics){.backend = "none", .selection = "kvm-requested-failure"};
  case DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_NOT_COMPILED:
    return diagnostic->requested == DAZE_BACKEND_REQUEST_KVM
             ? (DazeKvmSelectionMetrics){.backend = "none", .selection = "kvm-not-compiled"}
             : unicorn_request("kvm-not-compiled");
  case DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_NOT_COMPILED:
    return (DazeKvmSelectionMetrics){.backend = "none", .selection = "unicorn-not-compiled"};
  case DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE:
    return (DazeKvmSelectionMetrics){.backend = "none", .selection = "no-backend-available"};
  default:
    return (DazeKvmSelectionMetrics){.backend = "none", .selection = "kvm-invalid"};
  }
}
