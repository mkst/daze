#include "transition_writer.h"
#include "dpmi_process_state.h"
#include "guest_memory_layout.h"

#include <string.h>

static DazeKvmRealModeEntrySnapshot valid_entry(void) {
  return (DazeKvmRealModeEntrySnapshot){
    .valid = 1,
    .cs = 0x2200,
    .ds = 0x1010,
    .es = 0x1543,
    .fs = 0x0700,
    .gs = 0x0ff0,
    .ss = 0x1010,
    .sp = 0x4b02,
    .flags = 0x3202,
  };
}

int main(void) {
  uint8_t guest[0x10000];
  memset(guest, 0xa5, sizeof(guest));
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest)};
  const uint8_t first[] = {0x10, 0x11, 0x12};
  const uint8_t second[] = {0x20, 0x21};
  const DazeKvmTransitionWrite writes[] = {
    {.address = 0x20, .bytes = first, .size = sizeof(first)},
    {.address = 0x40, .bytes = second, .size = sizeof(second)},
  };
  const DazeKvmTransitionReservedRange reserved[] = {{.address = 0x80, .size = 8}};
  const DazeKvmTransitionWriterInput input = {
    .machine = &machine,
    .entry = &(DazeKvmRealModeEntrySnapshot){0},
    .resident_image_end = 0x20,
    .linear_min_address = 0x1000,
    .linear_limit = 0x8000,
    .writes = writes,
    .write_count = 2,
    .reserved_ranges = reserved,
    .reserved_range_count = 1,
  };
  DazeKvmRealModeEntrySnapshot entry = valid_entry();
  DazeKvmTransitionWriterInput valid = input;
  valid.entry = &entry;
  DazeDpmiProcessState state;
  memset(&state, 0x5a, sizeof(state));
  state.exception_vector_segment[13] = 0x0028;
  state.exception_vector_offset[13] = 0x5678;
  state.interrupt_vectors[0x21] = (DazeDpmiInterruptVector){0x0008, 0x0000095f};
  if (daze_kvm_transition_writer_apply(&valid, &state) != DAZE_KVM_TRANSITION_WRITER_OK ||
      memcmp(guest + 0x20, first, sizeof(first)) != 0 ||
      memcmp(guest + 0x40, second, sizeof(second)) != 0 ||
      state.linear_memory.first_base != 0x1000 || state.exception_vector_segment[13] != 0x0028 ||
      state.exception_vector_offset[13] != 0x5678 ||
      state.interrupt_vectors[0x21].segment != 0x0008 ||
      state.interrupt_vectors[0x21].offset != 0x0000095f)
    return 1;

  uint8_t before_guest[sizeof(guest)];
  memcpy(before_guest, guest, sizeof(guest));
  DazeDpmiProcessState before_state = state;
  const DazeKvmTransitionWrite overlap[] = {
    {.address = 0x50, .bytes = first, .size = sizeof(first)},
    {.address = 0x51, .bytes = second, .size = sizeof(second)},
  };
  DazeKvmTransitionWriterInput invalid = valid;
  invalid.writes = overlap;
  if (daze_kvm_transition_writer_apply(&invalid, &state) != DAZE_KVM_TRANSITION_WRITER_INVALID ||
      memcmp(guest, before_guest, sizeof(guest)) != 0 ||
      memcmp(&state, &before_state, sizeof(state)) != 0)
    return 1;
  const DazeKvmTransitionReservedRange colliding[] = {{.address = 0x20, .size = 1}};
  invalid = valid;
  invalid.reserved_ranges = colliding;
  if (daze_kvm_transition_writer_apply(&invalid, &state) != DAZE_KVM_TRANSITION_WRITER_INVALID ||
      memcmp(guest, before_guest, sizeof(guest)) != 0 ||
      memcmp(&state, &before_state, sizeof(state)) != 0)
    return 1;
  invalid = valid;
  invalid.writes = &(DazeKvmTransitionWrite){.address = 0x10000, .bytes = first, .size = 1};
  invalid.write_count = 1;
  if (daze_kvm_transition_writer_apply(&invalid, &state) != DAZE_KVM_TRANSITION_WRITER_INVALID ||
      memcmp(guest, before_guest, sizeof(guest)) != 0 ||
      memcmp(&state, &before_state, sizeof(state)) != 0)
    return 1;
  return 0;
}
