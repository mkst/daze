#include "dpmi_process_state.h"

int daze_dpmi_process_state_init(DazeDpmiProcessState *state, uint32_t resident_image_end,
                                 uint16_t ds, uint16_t return_cs,
                                 const DpmiAlternateState *snapshot, uint32_t linear_min_address,
                                 uint32_t linear_limit) {
  if (state == NULL || snapshot == NULL) return 0;
  uint32_t linear_first_base = 0;
  if (!daze_dpmi_linear_memory_first_base_after(resident_image_end, linear_min_address,
                                                linear_limit, &linear_first_base))
    return 0;
  DazeDpmiProcessState initialized = {0};
  daze_dpmi_linear_memory_init(&initialized.linear_memory, linear_first_base, linear_limit);
  initialized.next_ldt_index = k_dpmi_first_ldt_index;
  initialized.client_data_base = (uint32_t)ds << 4;
  initialized.client_code_base = (uint32_t)return_cs << 4;
  initialized.virtual_interrupts_enabled = 1;
  initialized.real_mode_state = *snapshot;
  initialized.real_mode_state_valid = 1;
  *state = initialized;
  return 1;
}
