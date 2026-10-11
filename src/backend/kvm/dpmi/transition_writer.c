#include "transition_writer.h"

#include "dpmi_process_state.h"
#include "kvm_range.h"

#include <string.h>

static int ranges_valid(const DazeKvmTransitionWriterInput *input) {
  const uint32_t guest_size = (uint32_t)input->machine->guest_size;
  if (input->machine->guest_size > UINT32_MAX || input->writes == NULL || input->write_count == 0 ||
      (input->reserved_range_count != 0 && input->reserved_ranges == NULL))
    return 0;
  for (size_t index = 0; index < input->write_count; ++index) {
    const DazeKvmTransitionWrite *write = input->writes + index;
    if (write->bytes == NULL ||
        !daze_kvm_range_fits_nonempty(guest_size, write->address, write->size))
      return 0;
    for (size_t previous = 0; previous < index; ++previous) {
      const DazeKvmTransitionWrite *other = input->writes + previous;
      if (daze_kvm_ranges_overlap(write->address, write->size, other->address, other->size))
        return 0;
    }
  }
  for (size_t index = 0; index < input->reserved_range_count; ++index) {
    const DazeKvmTransitionReservedRange *reserved = input->reserved_ranges + index;
    if (!daze_kvm_range_fits_nonempty(guest_size, reserved->address, reserved->size)) return 0;
    for (size_t previous = 0; previous < index; ++previous) {
      const DazeKvmTransitionReservedRange *other = input->reserved_ranges + previous;
      if (daze_kvm_ranges_overlap(reserved->address, reserved->size, other->address, other->size))
        return 0;
    }
    for (size_t write_index = 0; write_index < input->write_count; ++write_index) {
      const DazeKvmTransitionWrite *write = input->writes + write_index;
      if (daze_kvm_ranges_overlap(reserved->address, reserved->size, write->address, write->size))
        return 0;
    }
  }
  return 1;
}

int daze_kvm_transition_writer_input_valid(const DazeKvmTransitionWriterInput *input) {
  if (input == NULL || input->machine == NULL || input->machine->guest == NULL ||
      !ranges_valid(input))
    return 0;
  const DazeKvmTransitionStateInput state_input = {
    .guest_size = (uint32_t)input->machine->guest_size,
    .resident_image_end = input->resident_image_end,
    .linear_min_address = input->linear_min_address,
    .linear_limit = input->linear_limit,
    .writes = input->writes,
    .write_count = input->write_count,
  };
  return daze_kvm_transition_state_input_valid(input->entry, &state_input);
}

int daze_kvm_transition_writer_apply(const DazeKvmTransitionWriterInput *input,
                                     DazeDpmiProcessState *state) {
  if (state == NULL || !daze_kvm_transition_writer_input_valid(input))
    return DAZE_KVM_TRANSITION_WRITER_INVALID;
  /* Vector tables belong to the live client and must survive reconstruction of the
   * transition state. */
  uint16_t exception_vector_segment[32];
  uint16_t exception_vector_offset[32];
  DazeDpmiInterruptVector interrupt_vectors[256];
  memcpy(exception_vector_segment, state->exception_vector_segment,
         sizeof(exception_vector_segment));
  memcpy(exception_vector_offset, state->exception_vector_offset, sizeof(exception_vector_offset));
  memcpy(interrupt_vectors, state->interrupt_vectors, sizeof(interrupt_vectors));
  const DazeKvmTransitionStateInput state_input = {
    .guest_size = (uint32_t)input->machine->guest_size,
    .resident_image_end = input->resident_image_end,
    .linear_min_address = input->linear_min_address,
    .linear_limit = input->linear_limit,
    .writes = input->writes,
    .write_count = input->write_count,
  };
  if (daze_kvm_transition_state_prepare(input->entry, &state_input, state) !=
      DAZE_KVM_TRANSITION_STATE_OK)
    return DAZE_KVM_TRANSITION_WRITER_INVALID;
  for (size_t index = 0;
       index < sizeof(exception_vector_segment) / sizeof(exception_vector_segment[0]); ++index) {
    state->exception_vector_segment[index] = exception_vector_segment[index];
    state->exception_vector_offset[index] = exception_vector_offset[index];
  }
  memcpy(state->interrupt_vectors, interrupt_vectors, sizeof(interrupt_vectors));
  for (size_t index = 0; index < input->write_count; ++index) {
    const DazeKvmTransitionWrite *write = input->writes + index;
    memcpy((uint8_t *)input->machine->guest + write->address, write->bytes, write->size);
  }
  return DAZE_KVM_TRANSITION_WRITER_OK;
}
