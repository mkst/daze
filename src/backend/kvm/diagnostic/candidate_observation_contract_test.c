#include "candidate_observation.h"

#include <errno.h>
#include <string.h>

static int expect(DazeKvmMachineInitResult init, DazeKvmCandidateOutcome outcome,
                  DazeKvmSetupReason reason) {
  const DazeKvmCandidateObservation observation = daze_kvm_candidate_observation_from_init(&init);
  return memcmp(&observation.init, &init, sizeof(init)) == 0 && observation.outcome == outcome &&
         observation.reason == reason;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--host") == 0) {
    DazeKvmCandidateObservation host;
    DazeKvmMachine machine;
    if (!daze_kvm_candidate_prepare(8 * 1024 * 1024, &machine, &host)) return 1;
    if (host.init.status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
    const uint8_t byte = 0x5a;
    const int valid = host.init.status == DAZE_KVM_MACHINE_OK &&
                      host.outcome == DAZE_KVM_CANDIDATE_USABLE &&
                      host.reason == DAZE_KVM_SETUP_REASON_NONE && machine.vm >= 0 &&
                      machine.vcpu >= 0 && daze_kvm_machine_write(&machine, 0x100, &byte, 1) &&
                      ((const uint8_t *)machine.guest)[0x100] == byte;
    daze_kvm_machine_destroy(&machine);
    return valid ? 0 : 1;
  }
  if (argc != 1) return 2;
  DazeKvmCandidateObservation observation = {0};
  DazeKvmMachine machine;
  return expect((DazeKvmMachineInitResult){DAZE_KVM_MACHINE_OK, DAZE_KVM_MACHINE_STAGE_NONE, 0},
                DAZE_KVM_CANDIDATE_USABLE, DAZE_KVM_SETUP_REASON_NONE) &&
             expect((DazeKvmMachineInitResult){DAZE_KVM_MACHINE_UNAVAILABLE,
                                               DAZE_KVM_MACHINE_STAGE_OPEN, ENOENT},
                    DAZE_KVM_CANDIDATE_UNAVAILABLE, DAZE_KVM_SETUP_REASON_NO_DEVICE) &&
             expect((DazeKvmMachineInitResult){DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_VCPU,
                                               EIO},
                    DAZE_KVM_CANDIDATE_REJECTED, DAZE_KVM_SETUP_REASON_VCPU_CREATION) &&
             expect(
               (DazeKvmMachineInitResult){DAZE_KVM_MACHINE_INVALID, DAZE_KVM_MACHINE_STAGE_NONE, 0},
               DAZE_KVM_CANDIDATE_INVALID, DAZE_KVM_SETUP_REASON_INVALID) &&
             daze_kvm_candidate_observation_from_init(NULL).outcome == DAZE_KVM_CANDIDATE_INVALID &&
             !daze_kvm_candidate_prepare(1, &machine, NULL) &&
             !daze_kvm_candidate_prepare(1, NULL, &observation) &&
             daze_kvm_candidate_prepare(0, &machine, &observation) &&
             observation.outcome == DAZE_KVM_CANDIDATE_INVALID && machine.kvm == -1 &&
             machine.vm == -1 && machine.vcpu == -1 && machine.guest == NULL && machine.run == NULL
           ? 0
           : 1;
}
