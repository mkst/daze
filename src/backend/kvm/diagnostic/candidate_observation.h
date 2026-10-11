#ifndef DAZE_KVM_CANDIDATE_OBSERVATION_H
#define DAZE_KVM_CANDIDATE_OBSERVATION_H

#include "backend_selection.h"
#include "machine_diagnostic.h"

typedef struct {
  DazeKvmMachineInitResult init;
  DazeKvmCandidateOutcome outcome;
  DazeKvmSetupReason reason;
} DazeKvmCandidateObservation;

DazeKvmCandidateObservation
daze_kvm_candidate_observation_from_init(const DazeKvmMachineInitResult *init);

/* Initializes without running a guest. The caller owns a successful machine
 * until it transfers ownership to execution or destroys it. */
int daze_kvm_candidate_prepare(size_t guest_size, DazeKvmMachine *machine,
                               DazeKvmCandidateObservation *observation);

#endif
