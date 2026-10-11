#ifndef DAZE_KVM_TRANSITION_PLAN_H
#define DAZE_KVM_TRANSITION_PLAN_H

#include "transition_artifacts.h"
#include "transition_writer.h"

#include <stddef.h>
#include <stdint.h>

enum {
  DAZE_KVM_TRANSITION_PLAN_GDTR_OFFSET = 0x0080,
  DAZE_KVM_TRANSITION_PLAN_GDTR_SIZE = 6,
  DAZE_KVM_TRANSITION_PLAN_IDTR_OFFSET = 0x0086,
  DAZE_KVM_TRANSITION_PLAN_IDTR_SIZE = 6,
  DAZE_KVM_TRANSITION_PLAN_STATE_STUB_OFFSET = 0x0100,
  DAZE_KVM_TRANSITION_PLAN_STATE_STUB_SIZE = 4,
  DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_OFFSET = 0x0120,
  DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_SIZE = 3,
  /* Runner reservations are borrowed; the planner must not choose their placements. */
  DAZE_KVM_TRANSITION_PLAN_WRITE_COUNT = 8,
  DAZE_KVM_TRANSITION_PLAN_MAX_RESERVED_RANGES = 4,
};

/* Protected bases are explicit process addresses, never derived from selector numbers. */
typedef struct {
  uint32_t guest_size;
  uint32_t resident_image_end;
  uint16_t client_ds, client_ss;
  uint16_t return_ip, return_cs;
  uint16_t psp_segment, entry_segment;
  uint16_t environment_segment;
  int convert_environment;
  uint32_t gdt_address, ldt_address, idt_address;
  uint16_t idt_limit;
  uint32_t linear_min_address, linear_limit;
  const DazeDpmiTransitionDescriptorAddition *additions;
  size_t addition_count;
  /* Runner-owned ranges the transition writes must avoid, borrowed from the
   * caller for validation. NULL with a zero count skips the check. */
  const DazeKvmTransitionReservedRange *reserved_ranges;
  size_t reserved_range_count;
} DazeKvmTransitionPlanInput;

/* Write descriptors point into this object, so it must remain at a stable address until
 * installation. */
typedef struct {
  uint32_t trampoline_address;
  uint32_t resident_image_end;
  uint32_t linear_min_address;
  uint32_t linear_limit;
  DazeDpmiTransitionArtifacts artifacts;
  DazeKvmTransitionWrite writes[DAZE_KVM_TRANSITION_PLAN_WRITE_COUNT];
  size_t write_count;
  DazeKvmTransitionReservedRange reserved_ranges[DAZE_KVM_TRANSITION_PLAN_MAX_RESERVED_RANGES];
  size_t reserved_range_count;
} DazeKvmTransitionPlan;

typedef enum {
  DAZE_KVM_TRANSITION_PLAN_VALID = 0,
  DAZE_KVM_TRANSITION_PLAN_BAD_INPUT,
  /* first names the write that does not fit; second is empty. */
  DAZE_KVM_TRANSITION_PLAN_WRITE_OUT_OF_GUEST,
  /* first/second name the overlapping writes in write order. */
  DAZE_KVM_TRANSITION_PLAN_WRITE_OVERLAP,
  /* first names the reserved range that does not fit; second is empty. */
  DAZE_KVM_TRANSITION_PLAN_RESERVED_OUT_OF_GUEST,
  /* first names the write, second the reserved range it collides with. */
  DAZE_KVM_TRANSITION_PLAN_RESERVED_COLLISION,
  /* No page-aligned arena base exists below the limit; first carries
   * resident_image_end with size 0. */
  DAZE_KVM_TRANSITION_PLAN_NO_LINEAR_ARENA,
} DazeKvmTransitionPlanFailureKind;

typedef struct {
  DazeKvmTransitionPlanFailureKind kind;
  DazeKvmGuestRange first, second;
} DazeKvmTransitionPlanFailure;

int daze_kvm_transition_plan_build(const DazeKvmTransitionPlanInput *input,
                                   DazeKvmTransitionPlan *output,
                                   DazeKvmTransitionPlanFailure *failure);

void daze_kvm_transition_plan_report(const DazeKvmTransitionPlanInput *input,
                                     const DazeKvmTransitionPlanFailure *failure);

#endif
