#include "dpmi_process_state.h"

#include "guest_memory_layout.h"

#include <string.h>

int main(void) {
  const DpmiAlternateState snapshot = {.cs = 0x1234, .ds = 0x2345, .ss = 0x3456, .esp = 0x5678};
  DazeDpmiProcessState state = {0};
  if (!daze_dpmi_process_state_init(&state, 0x12345, 0x2345, 0x1234, &snapshot, 0x50000,
                                    0x7f0000) ||
      state.next_ldt_index != k_dpmi_first_ldt_index || state.client_data_base != 0x23450 ||
      state.client_code_base != 0x12340 || !state.virtual_interrupts_enabled ||
      !state.real_mode_state_valid ||
      memcmp(&state.real_mode_state, &snapshot, sizeof(snapshot)) != 0 ||
      state.linear_memory.first_base != 0x50000 || state.linear_memory.next_base != 0x50000 ||
      state.linear_memory.limit != 0x7f0000 || state.linear_memory.next_handle != 1)
    return 1;
  const DazeDpmiProcessState before = state;
  if (daze_dpmi_process_state_init(&state, 0x7f0000, 0x2345, 0x1234, &snapshot, 0x50000,
                                   0x7f0000) ||
      memcmp(&state, &before, sizeof(state)) != 0)
    return 1;
  if (daze_dpmi_process_state_init(NULL, 0x12345, 0x2345, 0x1234, &snapshot, 0x50000, 0x7f0000) ||
      daze_dpmi_process_state_init(&state, 0x12345, 0x2345, 0x1234, NULL, 0x50000, 0x7f0000))
    return 1;
  return 0;
}
