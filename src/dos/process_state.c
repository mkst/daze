#include "process_state.h"

#include <stddef.h>
#include <string.h>

#include "interrupt_vector.h"

void daze_dos_process_state_init(DazeDosProcessState *state, uint16_t psp_segment) {
  if (state == NULL) return;
  memset(state, 0, sizeof(*state));
  state->psp_segment = psp_segment;
  state->dta_segment = psp_segment;
  state->dta_offset = 0x0080;
}

void daze_dos_process_state_dispose(DazeDosProcessState *state) {
  if (state == NULL) return;
  daze_dosfs_find_close(&state->find);
}

void daze_dos_process_state_reinit_for_exec(DazeDosProcessState *state, uint16_t psp_segment) {
  if (state == NULL) return;
  uint16_t vector_segment[256];
  uint16_t vector_offset[256];
  memcpy(vector_segment, state->dos_vector_segment, sizeof(vector_segment));
  memcpy(vector_offset, state->dos_vector_offset, sizeof(vector_offset));
  /* An in-progress search does not survive EXEC: the child starts with fresh
   * find state, and dropping the open host directory here would leak it. */
  daze_dosfs_find_close(&state->find);
  daze_dos_process_state_init(state, psp_segment);
  memcpy(state->dos_vector_segment, vector_segment, sizeof(vector_segment));
  memcpy(state->dos_vector_offset, vector_offset, sizeof(vector_offset));
}

/* Initial vector model: 21h targets the DOS dispatch stub; 04h, 05h, and 0dh
 * share the IRET stub at offset 0010h. Other initialized vectors remain 0:0
 * until set by the guest through INT 21h/25h. */
void daze_dos_process_state_seed_vectors(DazeDosProcessState *state, uint16_t dos_vector_segment) {
  if (state == NULL) return;
  state->dos_vector_segment[DAZE_INT_DOS] = dos_vector_segment;
  state->dos_vector_offset[DAZE_INT_DOS] = 0;
  for (uint8_t vector = DAZE_INT_OVERFLOW; vector <= DAZE_INT_PRINT_SCREEN; ++vector) {
    state->dos_vector_segment[vector] = dos_vector_segment;
    state->dos_vector_offset[vector] = 0x0010;
  }
  state->dos_vector_segment[DAZE_INT_GP_FAULT] = dos_vector_segment;
  state->dos_vector_offset[DAZE_INT_GP_FAULT] = 0x0010;
}

void daze_dos_process_state_set_dta(DazeDosProcessState *state, uint16_t segment, uint16_t offset) {
  if (state == NULL) return;
  state->dta_segment = segment;
  state->dta_offset = offset;
}

uint32_t daze_dos_process_state_dta_linear(const DazeDosProcessState *state) {
  return state == NULL ? 0 : ((uint32_t)state->dta_segment << 4) + state->dta_offset;
}

int daze_dos_process_state_allocation_strategy(DazeDosProcessState *state, uint8_t subfunction,
                                               uint16_t bx, DazeDosAllocationStrategyReply *reply) {
  if (state == NULL || reply == NULL) return 0;
  *reply = (DazeDosAllocationStrategyReply){.ax = 1, .carry = 1};
  switch (subfunction) {
  case 0:
    reply->ax = state->allocation_strategy;
    reply->carry = 0;
    return 1;
  case 1:
    if (bx <= 2) {
      state->allocation_strategy = bx;
      reply->ax = 0;
      reply->carry = 0;
    }
    return 1;
  case 2:
    reply->ax = state->umb_link_enabled;
    reply->carry = 0;
    return 1;
  case 3:
    if (bx <= 1) {
      state->umb_link_enabled = (int)bx;
      reply->ax = 0;
      reply->carry = 0;
    }
    return 1;
  default:
    return 1;
  }
}

void daze_dos_process_state_record_child_termination(DazeDosProcessState *state,
                                                     uint8_t exit_status,
                                                     uint8_t termination_type) {
  if (state == NULL) return;
  state->child_exit_status = exit_status;
  state->child_termination_type = termination_type;
  state->child_status_available = 1;
}

int daze_dos_process_state_take_child_status(DazeDosProcessState *state,
                                             DazeDosChildStatusReply *reply) {
  if (state == NULL || reply == NULL) return 0;
  reply->ax = state->child_status_available
                ? (uint16_t)((state->child_termination_type << 8) | state->child_exit_status)
                : 0;
  state->child_status_available = 0;
  return 1;
}
