#include "transition_state.h"

#include "dpmi_process_state.h"
#include "kvm_range.h"

int daze_kvm_transition_state_input_valid(const DazeKvmRealModeEntrySnapshot *entry,
                                          const DazeKvmTransitionStateInput *input) {
  if (entry == NULL || !entry->valid || (entry->cr0 & 1u) != 0 || entry->ds == 0 ||
      entry->ss == 0 || input == NULL || input->writes == NULL || input->write_count == 0)
    return 0;
  for (size_t index = 0; index < input->write_count; ++index) {
    const DazeKvmTransitionWrite *write = input->writes + index;
    if (write->bytes == NULL ||
        !daze_kvm_range_fits_nonempty(input->guest_size, write->address, write->size))
      return 0;
  }
  return 1;
}

int daze_kvm_transition_state_prepare(const DazeKvmRealModeEntrySnapshot *entry,
                                      const DazeKvmTransitionStateInput *input,
                                      DazeDpmiProcessState *state) {
  if (state == NULL || !daze_kvm_transition_state_input_valid(entry, input))
    return DAZE_KVM_TRANSITION_STATE_INVALID;

  DpmiAlternateState real_mode_state = {
    .eax = entry->ax,
    .ebx = entry->bx,
    .ecx = entry->cx,
    .edx = entry->dx,
    .esi = entry->si,
    .edi = entry->di,
    .ebp = entry->bp,
    .esp = entry->sp,
    .eip = entry->ip,
    .eflags = entry->flags,
    .cs = entry->cs,
    .ds = entry->ds,
    .es = entry->es,
    .fs = entry->fs,
    .gs = entry->gs,
    .ss = entry->ss,
  };
  if (!daze_dpmi_process_state_init(state, input->resident_image_end, entry->ds, entry->cs,
                                    &real_mode_state, input->linear_min_address,
                                    input->linear_limit))
    return DAZE_KVM_TRANSITION_STATE_INVALID;
  return DAZE_KVM_TRANSITION_STATE_OK;
}
