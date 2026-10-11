#ifndef DAZE_DOSFS_PROCESS_STATE_H
#define DAZE_DOSFS_PROCESS_STATE_H

#include "dosfs.h"

#include <stdint.h>

typedef struct {
  uint16_t psp_segment;
  uint16_t dta_segment;
  uint16_t dta_offset;
  uint16_t allocation_strategy;
  int umb_link_enabled;
  uint8_t child_exit_status;
  uint8_t child_termination_type;
  int child_status_available;
  /* Reset on EXEC so temporary-name sequences remain deterministic per process. */
  uint32_t temp_file_counter;
  uint16_t dos_vector_segment[256];
  uint16_t dos_vector_offset[256];
  DazeDosfsFind find;
} DazeDosProcessState;

typedef struct {
  uint16_t ax;
  int carry;
} DazeDosAllocationStrategyReply;

typedef struct {
  uint16_t ax;
} DazeDosChildStatusReply;

void daze_dos_process_state_init(DazeDosProcessState *state, uint16_t psp_segment);
void daze_dos_process_state_dispose(DazeDosProcessState *state);
void daze_dos_process_state_seed_vectors(DazeDosProcessState *state, uint16_t dos_vector_segment);
/* Re-seat process identity for an EXEC child while preserving the live vector
 * table: vectors model the system-wide IVT, so the child inherits the
 * parent's table rather than a zeroed one. */
void daze_dos_process_state_reinit_for_exec(DazeDosProcessState *state, uint16_t psp_segment);
void daze_dos_process_state_set_dta(DazeDosProcessState *state, uint16_t segment, uint16_t offset);
uint32_t daze_dos_process_state_dta_linear(const DazeDosProcessState *state);
int daze_dos_process_state_allocation_strategy(DazeDosProcessState *state, uint8_t subfunction,
                                               uint16_t bx, DazeDosAllocationStrategyReply *reply);
void daze_dos_process_state_record_child_termination(DazeDosProcessState *state,
                                                     uint8_t exit_status, uint8_t termination_type);
int daze_dos_process_state_take_child_status(DazeDosProcessState *state,
                                             DazeDosChildStatusReply *reply);

#endif
