#ifndef DAZE_KVM_NORMAL_TRANSITION_CONFIG_H
#define DAZE_KVM_NORMAL_TRANSITION_CONFIG_H

#include "owner.h"
#include "process_layout.h"
#include "selector.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t guest_size, resident_image_end;
  uint16_t load_segment, psp_segment, environment_segment, dpmi_entry_segment;
  uint16_t dos_int21_vector_segment;
  uint16_t handoff_ds, handoff_ss, handoff_return_ip, handoff_return_cs;
  /* Runner-owned ranges the private gate area must avoid, borrowed from the
   * caller for validation. NULL with a zero count skips the check. */
  const DazeKvmGuestRange *reserved_ranges;
  size_t reserved_range_count;
} DazeKvmNormalTransitionConfigInput;

enum { DAZE_KVM_NORMAL_TRANSITION_CONFIG_MAX_ADDITIONS = 16 };

typedef enum {
  DAZE_KVM_NORMAL_TRANSITION_CONFIG_VALID = 0,
  DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT,
  /* first names the range that does not fit; second is empty. */
  DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OUT_OF_GUEST,
  /* first/second name the overlapping pair in check order. */
  DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OVERLAP,
} DazeKvmNormalTransitionConfigFailureKind;

typedef struct {
  DazeKvmNormalTransitionConfigFailureKind kind;
  DazeKvmGuestRange first, second;
} DazeKvmNormalTransitionConfigFailure;

/* All pointers in transition_layout and the three gate layouts point into
 * this caller-owned output object. It must remain at a stable address while a
 * later owner consumes transition_layout. */
typedef struct {
  DazeDpmiTransitionDescriptorAddition additions[DAZE_KVM_NORMAL_TRANSITION_CONFIG_MAX_ADDITIONS];
  size_t addition_count;
  DazeKvmProtectedGateLayout protected_gate;
  DazeKvmStateSaveGateLayout state_save_gate;
  DazeKvmRawSwitchGateLayout raw_switch_gate;
  DazeKvmCommandOwnerTransitionLayout transition_layout;
} DazeKvmNormalTransitionConfig;

/* Pure construction. Invalid input, a range overlap, or a selector collision
 * returns zero and leaves output unchanged. On failure with failure != NULL,
 * reports which ranges collided so the caller can reject loudly with names,
 * addresses, and phase. */
int daze_kvm_normal_transition_config_build(const DazeKvmNormalTransitionConfigInput *input,
                                            DazeKvmNormalTransitionConfig *output,
                                            DazeKvmNormalTransitionConfigFailure *failure);

void daze_kvm_normal_transition_config_report(const DazeKvmNormalTransitionConfigInput *input,
                                              const DazeKvmNormalTransitionConfigFailure *failure);

#endif
