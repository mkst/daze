#include "machine_diagnostic.h"

#include <errno.h>

DazeKvmSetupReason daze_kvm_machine_setup_reason(const DazeKvmMachineInitResult *result) {
  if (result == NULL) return DAZE_KVM_SETUP_REASON_INVALID;
  if (result->status == DAZE_KVM_MACHINE_OK) return DAZE_KVM_SETUP_REASON_NONE;
  if (result->status == DAZE_KVM_MACHINE_INVALID) return DAZE_KVM_SETUP_REASON_INVALID;
  if (result->status == DAZE_KVM_MACHINE_UNAVAILABLE) {
    if (result->stage != DAZE_KVM_MACHINE_STAGE_OPEN) return DAZE_KVM_SETUP_REASON_INVALID;
    if (result->error == ENOENT || result->error == ENODEV) return DAZE_KVM_SETUP_REASON_NO_DEVICE;
    if (result->error == EACCES || result->error == EPERM)
      return DAZE_KVM_SETUP_REASON_PERMISSION_DENIED;
    return DAZE_KVM_SETUP_REASON_UNUSABLE_DEVICE;
  }
  if (result->status != DAZE_KVM_MACHINE_FAILED) return DAZE_KVM_SETUP_REASON_INVALID;
  switch (result->stage) {
  case DAZE_KVM_MACHINE_STAGE_API:
    return DAZE_KVM_SETUP_REASON_API_MISMATCH;
  case DAZE_KVM_MACHINE_STAGE_VM:
    return DAZE_KVM_SETUP_REASON_VM_CREATION;
  case DAZE_KVM_MACHINE_STAGE_VCPU:
    return DAZE_KVM_SETUP_REASON_VCPU_CREATION;
  case DAZE_KVM_MACHINE_STAGE_MMAP_SIZE:
    return DAZE_KVM_SETUP_REASON_RUN_MAPPING_SIZE;
  case DAZE_KVM_MACHINE_STAGE_RUN_MMAP:
    return DAZE_KVM_SETUP_REASON_RUN_MAPPING;
  case DAZE_KVM_MACHINE_STAGE_GUEST_MMAP:
    return DAZE_KVM_SETUP_REASON_GUEST_MAPPING;
  case DAZE_KVM_MACHINE_STAGE_REGION:
    return DAZE_KVM_SETUP_REASON_MEMORY_REGISTRATION;
  default:
    return DAZE_KVM_SETUP_REASON_INVALID;
  }
}
