#include "result.h"

#include "owner_result.h"

#include <stddef.h>

DazeCommandResult daze_kvm_command_result_normalize(const DazeKvmCommandNormalizerInput *input) {
  DazeCommandResult result = {.disposition = DAZE_COMMAND_POSTSTART_FAILED};
  if (input == NULL) return result;
  result.guest_execution_started = input->guest_execution_started != 0;
  switch (input->disposition) {
  case DAZE_KVM_COMMAND_OWNER_TERMINATED:
    result.guest_execution_started = 1;
    if (input->exit_status_present) {
      result.disposition = DAZE_COMMAND_COMPLETED;
      result.dos_exit_code = input->exit_status;
    }
    return result;
  case DAZE_KVM_COMMAND_OWNER_PRESTART_REJECTED:
    result.disposition = DAZE_COMMAND_PRESTART_REJECTED;
    result.guest_execution_started = 0;
    return result;
  case DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED:
  case DAZE_KVM_COMMAND_OWNER_TRANSITION_BOUNDARY:
  case DAZE_KVM_COMMAND_OWNER_POST_SUCCESSOR_BOUNDARY:
    result.guest_execution_started = 1;
    return result;
  default:
    return result;
  }
}
