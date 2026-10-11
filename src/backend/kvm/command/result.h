#ifndef DAZE_KVM_COMMAND_RESULT_H
#define DAZE_KVM_COMMAND_RESULT_H

#include "command_result.h"

#include <stdint.h>

typedef struct {
  int disposition;
  int guest_execution_started;
  int exit_status_present;
  uint8_t exit_status;
} DazeKvmCommandNormalizerInput;

/* A nonterminal KVM owner boundary is never a successful DOS command. */
DazeCommandResult daze_kvm_command_result_normalize(const DazeKvmCommandNormalizerInput *input);

#endif
