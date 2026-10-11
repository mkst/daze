#ifndef DAZE_KVM_INT21_ADAPTER_H
#define DAZE_KVM_INT21_ADAPTER_H

#include "runner/runner_private.h"

DazeKvmPreflightBoundaryDisposition daze_kvm_int21_dispatch(
  DazeKvmMachine *machine, DazeDosfsFileService *files, DazeDosProcessState *process_state,
  DazeDosMemory *dos_memory, const uint8_t record[24],
  uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE], DazeKvmPreflightBoundaryResult *result);

#endif
