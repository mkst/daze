#include "transition_state.h"
#include "dpmi_process_state.h"
#include "guest_memory_layout.h"

#include <string.h>

int main(void) {
  const uint8_t transition_bytes[] = {
    0x90, /* nop */
    0x90  /* nop */
  };
  const DazeKvmTransitionWrite writes[] = {{0x2100, transition_bytes, sizeof(transition_bytes)}};
  const DazeKvmTransitionStateInput input = {
    .guest_size = 0x800000,
    .resident_image_end = 0x42000,
    .linear_min_address = 0x50000,
    .linear_limit = 0x7f0000,
    .writes = writes,
    .write_count = 1,
  };
  const DazeKvmRealModeEntrySnapshot entry = {
    .valid = 1,
    .cr0 = 0,
    .ax = 1,
    .bx = 2,
    .cx = 3,
    .dx = 4,
    .si = 5,
    .di = 6,
    .bp = 7,
    .cs = 0x2200,
    .ip = 2,
    .ds = 0x1010,
    .es = 0x1543,
    .fs = 0x0700,
    .gs = 0x0ff0,
    .ss = 0x1010,
    .sp = 0x4b02,
    .flags = 0x3202,
  };
  DazeDpmiProcessState state;
  memset(&state, 0xa5, sizeof(state));
  const DazeDpmiProcessState unchanged = state;
  DazeKvmRealModeEntrySnapshot invalid = entry;
  invalid.cr0 = 1;
  if (daze_kvm_transition_state_prepare(&invalid, &input, &state) !=
        DAZE_KVM_TRANSITION_STATE_INVALID ||
      memcmp(&state, &unchanged, sizeof(state)) != 0)
    return 1;
  if (daze_kvm_transition_state_prepare(&entry, &input, &state) != DAZE_KVM_TRANSITION_STATE_OK ||
      state.next_ldt_index != 16 || state.linear_memory.first_base != 0x50000 ||
      state.linear_memory.limit != input.linear_limit || state.client_data_base != 0x10100 ||
      state.client_code_base != 0x22000 || !state.virtual_interrupts_enabled ||
      !state.real_mode_state_valid || state.real_mode_state.eax != 1 ||
      state.real_mode_state.esp != 0x4b02 || state.real_mode_state.cs != 0x2200 ||
      state.real_mode_state.gs != 0x0ff0)
    return 1;
  DazeKvmRealModeEntrySnapshot zero_cs = entry;
  zero_cs.cs = 0;
  zero_cs.ip = 0x2002;
  if (daze_kvm_transition_state_prepare(&zero_cs, &input, &state) != DAZE_KVM_TRANSITION_STATE_OK ||
      state.client_code_base != 0 || state.real_mode_state.cs != 0 ||
      state.real_mode_state.eip != 0x2002)
    return 1;
  return 0;
}
