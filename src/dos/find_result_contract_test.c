#include "find_result.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  const DazeDosfsFindResult result = {.attributes = 0x20, .size = 0x12345678, .name = "PLAIN.C"};
  uint8_t dta[DAZE_DOS_FIND_DTA_SIZE];
  if (!daze_dos_find_result_encode(&result, dta) || dta[0x15] != 0x20 || dta[0x16] != 0 ||
      dta[0x17] != 0 || dta[0x18] != 0 || dta[0x19] != 0 || dta[0x1a] != 0x78 ||
      dta[0x1b] != 0x56 || dta[0x1c] != 0x34 || dta[0x1d] != 0x12 ||
      memcmp(dta + 0x1e, "PLAIN.C", sizeof("PLAIN.C")) != 0) {
    fprintf(stderr, "DTA encoding failed\n");
    return 1;
  }
  return 0;
}
