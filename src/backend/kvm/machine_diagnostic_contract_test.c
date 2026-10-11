#include "machine_candidate.h"
#include "machine_diagnostic.h"

#include <errno.h>

static int expect(int status, int stage, int error, DazeKvmSetupReason expected) {
  DazeKvmMachineInitResult result = {.status = status, .stage = stage, .error = error};
  return daze_kvm_machine_setup_reason(&result) == expected;
}

int main(void) {
  return expect(DAZE_KVM_MACHINE_OK, DAZE_KVM_MACHINE_STAGE_NONE, 0, DAZE_KVM_SETUP_REASON_NONE) &&
             expect(DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_OPEN, ENOENT,
                    DAZE_KVM_SETUP_REASON_NO_DEVICE) &&
             expect(DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_OPEN, ENODEV,
                    DAZE_KVM_SETUP_REASON_NO_DEVICE) &&
             expect(DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_OPEN, EACCES,
                    DAZE_KVM_SETUP_REASON_PERMISSION_DENIED) &&
             expect(DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_OPEN, EPERM,
                    DAZE_KVM_SETUP_REASON_PERMISSION_DENIED) &&
             expect(DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_OPEN, EIO,
                    DAZE_KVM_SETUP_REASON_UNUSABLE_DEVICE) &&
             expect(DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_API, 0,
                    DAZE_KVM_SETUP_REASON_API_MISMATCH) &&
             expect(DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_VM, EIO,
                    DAZE_KVM_SETUP_REASON_VM_CREATION) &&
             expect(DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_VCPU, EIO,
                    DAZE_KVM_SETUP_REASON_VCPU_CREATION) &&
             expect(DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_MMAP_SIZE, 0,
                    DAZE_KVM_SETUP_REASON_RUN_MAPPING_SIZE) &&
             expect(DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_RUN_MMAP, ENOMEM,
                    DAZE_KVM_SETUP_REASON_RUN_MAPPING) &&
             expect(DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_GUEST_MMAP, ENOMEM,
                    DAZE_KVM_SETUP_REASON_GUEST_MAPPING) &&
             expect(DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_REGION, EINVAL,
                    DAZE_KVM_SETUP_REASON_MEMORY_REGISTRATION) &&
             expect(DAZE_KVM_MACHINE_INVALID, DAZE_KVM_MACHINE_STAGE_NONE, 0,
                    DAZE_KVM_SETUP_REASON_INVALID) &&
             expect(99, DAZE_KVM_MACHINE_STAGE_NONE, 0, DAZE_KVM_SETUP_REASON_INVALID) &&
             expect(DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_VM, EIO,
                    DAZE_KVM_SETUP_REASON_INVALID) &&
             daze_kvm_machine_setup_reason(NULL) == DAZE_KVM_SETUP_REASON_INVALID
           ? 0
           : 1;
}
