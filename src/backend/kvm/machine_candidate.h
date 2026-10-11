#ifndef DAZE_KVM_MACHINE_CANDIDATE_H
#define DAZE_KVM_MACHINE_CANDIDATE_H

#include "backend_selection.h"
#include "machine_private.h"

DazeKvmCandidateOutcome daze_kvm_machine_candidate_outcome(const DazeKvmMachineInitResult *result);

#endif
