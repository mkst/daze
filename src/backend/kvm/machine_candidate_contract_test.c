#include "machine_candidate.h"

static int expect(int status, int stage, int error, DazeKvmCandidateOutcome expected) {
  DazeKvmMachineInitResult result = {.status = status, .stage = stage, .error = error};
  const DazeKvmCandidateOutcome outcome = daze_kvm_machine_candidate_outcome(&result);
  return outcome == expected && result.stage == stage && result.error == error;
}

int main(void) {
  return expect(DAZE_KVM_MACHINE_OK, DAZE_KVM_MACHINE_STAGE_NONE, 0, DAZE_KVM_CANDIDATE_USABLE) &&
             expect(DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_OPEN, 13,
                    DAZE_KVM_CANDIDATE_UNAVAILABLE) &&
             expect(DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_VCPU, 5,
                    DAZE_KVM_CANDIDATE_REJECTED) &&
             expect(DAZE_KVM_MACHINE_INVALID, DAZE_KVM_MACHINE_STAGE_NONE, 0,
                    DAZE_KVM_CANDIDATE_INVALID) &&
             expect(99, DAZE_KVM_MACHINE_STAGE_REGION, 22, DAZE_KVM_CANDIDATE_INVALID) &&
             daze_kvm_machine_candidate_outcome(NULL) == DAZE_KVM_CANDIDATE_INVALID
           ? 0
           : 1;
}
