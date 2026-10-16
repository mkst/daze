#ifndef DAZE_KVM_LEGACY_EXCEPTION_H
#define DAZE_KVM_LEGACY_EXCEPTION_H
#include "interrupt_vector.h"
#include "protected.h"
#include "dpmi_process_state.h"

/* Accepted KVM fixtures require one active delivery at a time. Reject nested
 * faults explicitly until their locked-stack ownership is separately proved. */
enum {
  DAZE_KVM_LEGACY_NP_MARKER = 0x1b,
  DAZE_KVM_LEGACY_RETURN_MARKER = 0x1c,
  DAZE_KVM_LEGACY_MAX_DEPTH = 1
};
typedef struct {
  uint32_t frame_linear, return_linear;
  uint16_t frame_sp, selector;
  uint16_t return_ip, return_cs;
  int native_return;
} DazeKvmLegacyExceptionDelivery;
typedef struct {
  DazeKvmLegacyExceptionDelivery deliveries[DAZE_KVM_LEGACY_MAX_DEPTH];
  size_t depth;
} DazeKvmLegacyExceptionState;

/* Captures the 16-bit legacy #NP ABI through the host-owned 32-bit code alias. */
int daze_kvm_legacy_exception_install(DazeKvmMachine *machine,
                                      const DazeKvmProtectedGateLayout *gate);
/* Returns 1 for a handled capture/return, 0 for another boundary, -1 on an
 * unsupported or invalid fault. CPU state remains parked on refusal. */
int daze_kvm_legacy_exception_boundary(DazeKvmMachine *machine,
                                       const DazeKvmProtectedGateLayout *gate,
                                       const DazeDpmiProcessState *process,
                                       DazeKvmLegacyExceptionState *state,
                                       DazeKvmDpmiEntryResult *boundary);
int daze_kvm_legacy_exception_rearm(DazeKvmMachine *machine,
                                    const DazeKvmLegacyExceptionState *state);
int daze_kvm_legacy_exception_reconcile(DazeKvmMachine *machine, DazeKvmLegacyExceptionState *state,
                                        const DazeKvmDpmiEntryResult *boundary);
int daze_kvm_legacy_exception_guest_return(const DazeKvmLegacyExceptionState *state);
void daze_kvm_legacy_exception_host_return(DazeKvmMachine *machine,
                                           const DazeKvmLegacyExceptionState *state);
#endif
