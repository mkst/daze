#include "result.h"

#include "owner_result.h"

#include <stddef.h>

static int matches(const DazeCommandResult *result, DazeCommandDisposition disposition,
                   uint8_t exit_code, int started) {
  return result->disposition == disposition && result->dos_exit_code == exit_code &&
         result->guest_execution_started == started;
}

int main(void) {
  DazeKvmCommandNormalizerInput input = {
    .disposition = DAZE_KVM_COMMAND_OWNER_TERMINATED,
    .guest_execution_started = 1,
    .exit_status_present = 1,
    .exit_status = 0,
  };
  DazeCommandResult result = daze_kvm_command_result_normalize(&input);
  if (!matches(&result, DAZE_COMMAND_COMPLETED, 0, 1)) return 1;
  input.exit_status = 9;
  result = daze_kvm_command_result_normalize(&input);
  if (!matches(&result, DAZE_COMMAND_COMPLETED, 9, 1)) return 1;
  input.exit_status_present = 0;
  result = daze_kvm_command_result_normalize(&input);
  if (!matches(&result, DAZE_COMMAND_POSTSTART_FAILED, 0, 1)) return 1;
  input.disposition = DAZE_KVM_COMMAND_OWNER_PRESTART_REJECTED;
  input.guest_execution_started = 1;
  result = daze_kvm_command_result_normalize(&input);
  if (!matches(&result, DAZE_COMMAND_PRESTART_REJECTED, 0, 0)) return 1;
  input.disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  result = daze_kvm_command_result_normalize(&input);
  if (!matches(&result, DAZE_COMMAND_POSTSTART_FAILED, 0, 1)) return 1;
  input.disposition = DAZE_KVM_COMMAND_OWNER_TRANSITION_BOUNDARY;
  result = daze_kvm_command_result_normalize(&input);
  if (!matches(&result, DAZE_COMMAND_POSTSTART_FAILED, 0, 1)) return 1;
  input.disposition = DAZE_KVM_COMMAND_OWNER_POST_SUCCESSOR_BOUNDARY;
  input.exit_status_present = 1;
  input.exit_status = 0x21;
  result = daze_kvm_command_result_normalize(&input);
  if (!matches(&result, DAZE_COMMAND_POSTSTART_FAILED, 0, 1)) return 1;
  input.disposition = 99;
  input.guest_execution_started = 0;
  result = daze_kvm_command_result_normalize(&input);
  if (!matches(&result, DAZE_COMMAND_POSTSTART_FAILED, 0, 0)) return 1;
  result = daze_kvm_command_result_normalize(NULL);
  if (!matches(&result, DAZE_COMMAND_POSTSTART_FAILED, 0, 0)) return 1;
  return 0;
}
