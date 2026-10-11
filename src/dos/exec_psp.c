#include "exec_psp.h"

#include <stddef.h>
#include <string.h>

int daze_dos_exec_psp_build(uint16_t psp_segment, uint16_t parent_psp_segment,
                            uint16_t environment_segment, uint16_t dos_vector_segment,
                            const uint8_t tail[127], const uint8_t fcb1[16], const uint8_t fcb2[16],
                            uint8_t output[DAZE_DOS_EXEC_PSP_SIZE]) {
  if (tail == NULL || fcb1 == NULL || fcb2 == NULL || output == NULL || tail[0] > 126) return 0;
  memset(output, 0, DAZE_DOS_EXEC_PSP_SIZE);
  output[0] = 0xcd;
  output[1] = 0x20;
  output[2] = 0xff;
  output[3] = 0x9f;
  for (size_t offset = 0x0a; offset <= 0x12; offset += 4) {
    output[offset] = 0x10;
    output[offset + 2] = (uint8_t)dos_vector_segment;
    output[offset + 3] = (uint8_t)(dos_vector_segment >> 8);
  }
  output[0x16] = (uint8_t)parent_psp_segment;
  output[0x17] = (uint8_t)(parent_psp_segment >> 8);
  memset(output + 0x18, 0xff, 20);
  for (uint8_t i = 0; i < 5; ++i)
    output[0x18 + i] = i;
  output[0x2c] = (uint8_t)environment_segment;
  output[0x2d] = (uint8_t)(environment_segment >> 8);
  output[0x32] = 20;
  output[0x34] = 0x18;
  output[0x36] = (uint8_t)psp_segment;
  output[0x37] = (uint8_t)(psp_segment >> 8);
  memset(output + 0x38, 0xff, 4);
  output[0x50] = 0xcd;
  output[0x51] = 0x21;
  output[0x52] = 0xcb;
  memcpy(output + 0x5c, fcb1, 16);
  memcpy(output + 0x6c, fcb2, 16);
  output[0x80] = tail[0];
  memcpy(output + 0x81, tail + 1, tail[0]);
  output[0x81 + tail[0]] = '\r';
  return 1;
}
