#ifndef DAZE_DOS_FIND_RESULT_H
#define DAZE_DOS_FIND_RESULT_H

#include "dosfs.h"

#include <stdint.h>

enum { DAZE_DOS_FIND_DTA_SIZE = 43 };

/* Encodes the fixed DOS 2+ Find First/Next DTA result used by both execution
 * backends. Timestamp bytes deliberately remain zero. */
int daze_dos_find_result_encode(const DazeDosfsFindResult *result,
                                uint8_t output[DAZE_DOS_FIND_DTA_SIZE]);

#endif
