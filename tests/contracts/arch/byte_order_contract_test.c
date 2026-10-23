#include "byte_order.h"

#include <stdio.h>

int main(void) {
  const uint8_t input[] = {0x78, 0x56, 0x34, 0x12};
  uint8_t output[4] = {0};
  daze_write_u16(output, 0x5678);
  daze_write_u32(output, 0x12345678u);
  const int pass = daze_read_u16(input) == 0x5678 && daze_read_u32(input) == 0x12345678u &&
                   output[0] == 0x78 && output[1] == 0x56 && output[2] == 0x34 && output[3] == 0x12;
  fprintf(stderr, "byte-order contract test: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
