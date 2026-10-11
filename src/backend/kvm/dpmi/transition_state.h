#ifndef DAZE_KVM_DPMI_TRANSITION_STATE_H
#define DAZE_KVM_DPMI_TRANSITION_STATE_H

#include "kvm_guest_write.h"
#include "runner_request_common.h"

#include <stddef.h>
#include <stdint.h>

typedef struct DazeDpmiProcessState DazeDpmiProcessState;

typedef DazeKvmGuestWrite DazeKvmTransitionWrite;

typedef struct {
  uint32_t guest_size;
  uint32_t resident_image_end;
  uint32_t linear_min_address;
  uint32_t linear_limit;
  const DazeKvmTransitionWrite *writes;
  size_t write_count;
} DazeKvmTransitionStateInput;

enum {
  DAZE_KVM_TRANSITION_STATE_OK = 0,
  DAZE_KVM_TRANSITION_STATE_INVALID = 2,
};

/* Pure validation for callers that need to reject a complete composed
 * transition before publishing state or mutating guest memory. */
int daze_kvm_transition_state_input_valid(const DazeKvmRealModeEntrySnapshot *entry,
                                          const DazeKvmTransitionStateInput *input);

/* Invalid transition facts leave state unchanged. */
int daze_kvm_transition_state_prepare(const DazeKvmRealModeEntrySnapshot *entry,
                                      const DazeKvmTransitionStateInput *input,
                                      DazeDpmiProcessState *state);

#endif
