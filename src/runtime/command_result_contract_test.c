#include <stddef.h>

#include "command_result.h"

static int expect(const DazeCommandResult *result, int host_status) {
  return daze_command_result_host_status(result) == host_status;
}

int main(void) {
  const DazeCommandResult completed0 = {
    .disposition = DAZE_COMMAND_COMPLETED, .dos_exit_code = 0, .guest_execution_started = 1};
  const DazeCommandResult completed9 = {
    .disposition = DAZE_COMMAND_COMPLETED, .dos_exit_code = 9, .guest_execution_started = 1};
  const DazeCommandResult prestart_rejected = {.disposition = DAZE_COMMAND_PRESTART_REJECTED};
  const DazeCommandResult poststart_failed = {.disposition = DAZE_COMMAND_POSTSTART_FAILED,
                                              .guest_execution_started = 1};
  const DazeCommandResult unknown = {.disposition = (DazeCommandDisposition)99};
  return expect(&completed0, 0) && expect(&completed9, 9) && expect(&prestart_rejected, 3) &&
             expect(&poststart_failed, 1) && expect(&unknown, 1) && expect(NULL, 1)
           ? 0
           : 1;
}
