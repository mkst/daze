#include "process_state.h"

#undef NDEBUG
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  DazeDosProcessState state = {0};
  daze_dos_process_state_init(&state, 0x0ff0);
  if (state.dta_segment != 0x0ff0 || state.dta_offset != 0x0080 ||
      state.dos_vector_segment[0x1b] != 0 || state.dos_vector_offset[0x1b] != 0 ||
      daze_dos_process_state_dta_linear(&state) != 0x0ff80)
    return 1;
  daze_dos_process_state_seed_vectors(&state, 0x0300);
  if (state.dos_vector_segment[0x21] != 0x0300 || state.dos_vector_offset[0x21] != 0 ||
      state.dos_vector_segment[0x04] != 0x0300 || state.dos_vector_offset[0x04] != 0x0010 ||
      state.dos_vector_segment[0x05] != 0x0300 || state.dos_vector_offset[0x05] != 0x0010 ||
      state.dos_vector_segment[0x0d] != 0x0300 || state.dos_vector_offset[0x0d] != 0x0010 ||
      state.dos_vector_segment[0x1b] != 0 || state.dos_vector_offset[0x1b] != 0)
    return 1;
  daze_dos_process_state_set_dta(&state, 0x2345, 0x4567);
  if (state.dta_segment != 0x2345 || state.dta_offset != 0x4567 ||
      daze_dos_process_state_dta_linear(&state) != 0x279b7)
    return 1;
  /* EXEC re-seats identity but preserves the live vector table: vectors model
   * the system-wide IVT, which the child inherits from the parent. */
  state.dos_vector_segment[0x21] = 0x1234;
  state.dos_vector_offset[0x21] = 0x5678;
  state.dos_vector_segment[0x1b] = 0x9abc;
  daze_dos_process_state_reinit_for_exec(&state, 0x2000);
  if (state.psp_segment != 0x2000 || state.dta_segment != 0x2000 || state.dta_offset != 0x0080 ||
      state.dos_vector_segment[0x21] != 0x1234 || state.dos_vector_offset[0x21] != 0x5678 ||
      state.dos_vector_segment[0x1b] != 0x9abc || state.dos_vector_segment[0x04] != 0x0300 ||
      state.dos_vector_offset[0x04] != 0x0010)
    return 1;
  DazeDosAllocationStrategyReply reply;
  if (!daze_dos_process_state_allocation_strategy(&state, 0, 0, &reply) || reply.ax != 0 ||
      reply.carry || !daze_dos_process_state_allocation_strategy(&state, 1, 2, &reply) ||
      reply.carry || !daze_dos_process_state_allocation_strategy(&state, 0, 0, &reply) ||
      reply.ax != 2 || reply.carry ||
      !daze_dos_process_state_allocation_strategy(&state, 1, 3, &reply) || !reply.carry)
    return 1;
  DazeDosChildStatusReply child_status;
  daze_dos_process_state_record_child_termination(&state, 1, 0);
  if (!daze_dos_process_state_take_child_status(&state, &child_status) || child_status.ax != 1 ||
      !daze_dos_process_state_take_child_status(&state, &child_status) || child_status.ax != 0)
    return 1;
  assert(daze_dos_process_state_allocation_strategy(&state, 3, 1, &reply) && !reply.carry);
  assert(daze_dos_process_state_allocation_strategy(&state, 2, 0, &reply) && reply.ax == 1 &&
         !reply.carry);
  assert(daze_dos_process_state_allocation_strategy(&state, 3, 2, &reply) && reply.ax == 1 &&
         reply.carry && state.umb_link_enabled == 1);
  assert(daze_dos_process_state_allocation_strategy(&state, 3, 0, &reply) && !reply.carry);
  assert(daze_dos_process_state_allocation_strategy(&state, 2, 0, &reply) && reply.ax == 0 &&
         !reply.carry);
  assert(daze_dos_process_state_allocation_strategy(&state, 255, 0, &reply) && reply.ax == 1 &&
         reply.carry);
  daze_dos_process_state_record_child_termination(&state, 37, 2);
  assert(daze_dos_process_state_take_child_status(&state, &child_status) &&
         child_status.ax == 0x225);
  assert(daze_dos_process_state_take_child_status(&state, &child_status) && child_status.ax == 0);
  char directory[] = "/tmp/daze-process-state-XXXXXX";
  assert(mkdtemp(directory) != NULL);
  state.find.directory = opendir(directory);
  assert(state.find.directory != NULL);
  int search_fd = dirfd(state.find.directory);
  daze_dos_process_state_reinit_for_exec(&state, 0x3000);
  assert(state.find.directory == NULL && fcntl(search_fd, F_GETFD) == -1 &&
         !state.child_status_available && state.allocation_strategy == 0 &&
         !state.umb_link_enabled && state.psp_segment == 0x3000);
  state.find.directory = opendir(directory);
  assert(state.find.directory != NULL);
  search_fd = dirfd(state.find.directory);
  daze_dos_process_state_dispose(&state);
  assert(state.find.directory == NULL && fcntl(search_fd, F_GETFD) == -1);
  daze_dos_process_state_dispose(&state);
  assert(rmdir(directory) == 0);
  daze_dos_process_state_init(NULL, 0);
  daze_dos_process_state_dispose(NULL);
  daze_dos_process_state_reinit_for_exec(NULL, 0);
  daze_dos_process_state_seed_vectors(NULL, 0);
  daze_dos_process_state_set_dta(NULL, 0, 0);
  daze_dos_process_state_record_child_termination(NULL, 0, 0);
  assert(daze_dos_process_state_dta_linear(NULL) == 0);
  assert(!daze_dos_process_state_allocation_strategy(NULL, 0, 0, &reply));
  assert(!daze_dos_process_state_allocation_strategy(&state, 0, 0, NULL));
  assert(!daze_dos_process_state_take_child_status(NULL, &child_status));
  assert(!daze_dos_process_state_take_child_status(&state, NULL));
  puts("DOS process state contract test: passed");
  return 0;
}
