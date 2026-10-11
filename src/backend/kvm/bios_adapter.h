#ifndef DAZE_KVM_BIOS_ADAPTER_H
#define DAZE_KVM_BIOS_ADAPTER_H

#include "runner/runner_private.h"

/* Unsupported requests leave the reply mailbox unchanged. */
DazeKvmPreflightBoundaryDisposition
daze_kvm_bios_dispatch(const uint8_t record[24],
                       uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE]);

#endif
