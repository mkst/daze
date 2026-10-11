#ifndef DAZE_UNICORN_RUN_H
#define DAZE_UNICORN_RUN_H

#include "command_result.h"

struct DazePreparedLaunch;
struct DazeUnicornContext;

DazeCommandResult daze_unicorn_run_prepared(struct DazePreparedLaunch *launch,
                                            struct DazeUnicornContext *context, const char *path);

#endif
