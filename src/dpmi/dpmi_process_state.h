#ifndef DAZE_DPMI_PROCESS_STATE_H
#define DAZE_DPMI_PROCESS_STATE_H

#include "alternate_state.h"
#include "linear_memory.h"
#include "request.h"

#include <stdint.h>

enum {
  k_dpmi_ldt_size = 65536,
  k_dpmi_first_ldt_index = 16,
};

typedef struct DazeDpmiProcessState {
  uint16_t next_ldt_index;
  uint8_t ldt_used[k_dpmi_ldt_size / 8];
  uint16_t exception_vector_segment[32];
  uint16_t exception_vector_offset[32];
  uint16_t real_mode_vector_segment[256];
  uint16_t real_mode_vector_offset[256];
  DazeDpmiInterruptVector interrupt_vectors[256];
  int virtual_interrupts_enabled;
  DazeDpmiLinearMemory linear_memory;
  uint32_t client_data_base;
  uint32_t client_code_base;
  DpmiAlternateState real_mode_state;
  int real_mode_state_valid;
} DazeDpmiProcessState;

int daze_dpmi_process_state_init(DazeDpmiProcessState *state, uint32_t resident_image_end,
                                 uint16_t ds, uint16_t return_cs,
                                 const DpmiAlternateState *snapshot, uint32_t linear_min_address,
                                 uint32_t linear_limit);

#endif
