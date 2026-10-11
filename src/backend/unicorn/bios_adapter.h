#ifndef DAZE_BIOS_H
#define DAZE_BIOS_H

#include <stdint.h>

#include "unicorn_context.h"

int daze_bios_dispatch(uc_engine *uc, uint8_t interrupt, const DazeUnicornEngine *engine,
                       DazeUnicornRunState *run);

#endif
