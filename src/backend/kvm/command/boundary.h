#ifndef DAZE_KVM_COMMAND_BOUNDARY_H
#define DAZE_KVM_COMMAND_BOUNDARY_H

#include "entry.h"

typedef enum {
  DAZE_KVM_COMMAND_BOUNDARY_UNSUPPORTED,
  DAZE_KVM_COMMAND_BOUNDARY_MEDIATOR,
  DAZE_KVM_COMMAND_BOUNDARY_STATE,
  DAZE_KVM_COMMAND_BOUNDARY_RAW,
  DAZE_KVM_COMMAND_BOUNDARY_RUNNER,
  DAZE_KVM_COMMAND_BOUNDARY_OTHER,
} DazeKvmCommandBoundaryKind;

DazeKvmCommandBoundaryKind
daze_kvm_command_boundary_classify(const DazeKvmDpmiEntryResult *boundary);

#endif
