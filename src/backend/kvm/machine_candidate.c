#include "machine_candidate.h"

DazeKvmCandidateOutcome daze_kvm_machine_candidate_outcome(const DazeKvmMachineInitResult *result) {
  if (result == NULL) return DAZE_KVM_CANDIDATE_INVALID;
  switch (result->status) {
  case DAZE_KVM_MACHINE_OK:
    return DAZE_KVM_CANDIDATE_USABLE;
  case DAZE_KVM_MACHINE_UNAVAILABLE:
    return DAZE_KVM_CANDIDATE_UNAVAILABLE;
  case DAZE_KVM_MACHINE_FAILED:
    return DAZE_KVM_CANDIDATE_REJECTED;
  case DAZE_KVM_MACHINE_INVALID:
  default:
    return DAZE_KVM_CANDIDATE_INVALID;
  }
}
