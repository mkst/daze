#include <stddef.h>

#include "command_result.h"

int daze_command_result_host_status(const DazeCommandResult *result) {
  if (result == NULL) return 1;
  switch (result->disposition) {
  case DAZE_COMMAND_COMPLETED:
    return result->dos_exit_code;
  case DAZE_COMMAND_PRESTART_REJECTED:
    return 3;
  case DAZE_COMMAND_POSTSTART_FAILED:
  default:
    return 1;
  }
}
