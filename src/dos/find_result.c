#include "find_result.h"

#include <string.h>

int daze_dos_find_result_encode(const DazeDosfsFindResult *result,
                                uint8_t output[DAZE_DOS_FIND_DTA_SIZE]) {
  if (result == NULL || output == NULL) return 0;
  memset(output, 0, DAZE_DOS_FIND_DTA_SIZE);
  output[0x15] = result->attributes;
  memcpy(output + 0x1a, &result->size, sizeof(result->size));
  memcpy(output + 0x1e, result->name, sizeof(result->name));
  return 1;
}
