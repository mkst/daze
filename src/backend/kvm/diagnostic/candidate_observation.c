#include "candidate_observation.h"

#include "machine_candidate.h"

DazeKvmCandidateObservation
daze_kvm_candidate_observation_from_init(const DazeKvmMachineInitResult *init) {
  const DazeKvmMachineInitResult invalid = {
    .status = DAZE_KVM_MACHINE_INVALID, .stage = DAZE_KVM_MACHINE_STAGE_NONE, .error = 0};
  const DazeKvmMachineInitResult value = init == NULL ? invalid : *init;
  const DazeKvmCandidateOutcome outcome = daze_kvm_machine_candidate_outcome(&value);
  return (DazeKvmCandidateObservation){
    .init = value,
    .outcome = outcome,
    .reason = daze_kvm_machine_setup_reason(&value),
  };
}

int daze_kvm_candidate_prepare(size_t guest_size, DazeKvmMachine *machine,
                               DazeKvmCandidateObservation *observation) {
  if (machine == NULL || observation == NULL) return 0;
  *machine = (DazeKvmMachine){.kvm = -1, .vm = -1, .vcpu = -1};
  const DazeKvmMachineInitResult init = daze_kvm_machine_init_with_seam(machine, guest_size, NULL);
  *observation = daze_kvm_candidate_observation_from_init(&init);
  return 1;
}
