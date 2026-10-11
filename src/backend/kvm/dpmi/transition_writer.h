#ifndef DAZE_KVM_DPMI_TRANSITION_WRITER_H
#define DAZE_KVM_DPMI_TRANSITION_WRITER_H

#include "transition_state.h"
#include "machine.h"
#include "process_layout.h"

#include <stddef.h>
#include <stdint.h>

typedef DazeKvmGuestRange DazeKvmTransitionReservedRange;

typedef struct {
  DazeKvmMachine *machine;
  const DazeKvmRealModeEntrySnapshot *entry;
  uint32_t resident_image_end;
  uint32_t linear_min_address;
  uint32_t linear_limit;
  const DazeKvmTransitionWrite *writes;
  size_t write_count;
  const DazeKvmTransitionReservedRange *reserved_ranges;
  size_t reserved_range_count;
} DazeKvmTransitionWriterInput;

enum {
  DAZE_KVM_TRANSITION_WRITER_OK = 0,
  DAZE_KVM_TRANSITION_WRITER_INVALID = 2,
};

int daze_kvm_transition_writer_input_valid(const DazeKvmTransitionWriterInput *input);

/* Install validated artifacts into mapped guest memory without running the guest. */
int daze_kvm_transition_writer_apply(const DazeKvmTransitionWriterInput *input,
                                     DazeDpmiProcessState *state);

#endif
