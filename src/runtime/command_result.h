#ifndef DAZE_COMMAND_RESULT_H
#define DAZE_COMMAND_RESULT_H

#include <stdint.h>

/* A completed DOS command is distinct from a backend setup rejection and a
 * failure after guest execution has begun. */
typedef enum {
  DAZE_COMMAND_COMPLETED,
  DAZE_COMMAND_PRESTART_REJECTED,
  DAZE_COMMAND_POSTSTART_FAILED,
} DazeCommandDisposition;

typedef struct {
  DazeCommandDisposition disposition;
  uint8_t dos_exit_code;
  int guest_execution_started;
} DazeCommandResult;

/* Only completed DOS commands return their DOS status; setup rejection is 3 and other
 * failures are 1. */
int daze_command_result_host_status(const DazeCommandResult *result);

#endif
