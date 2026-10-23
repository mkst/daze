#include "exec_psp.h"

#include <string.h>

int main(void) {
  uint8_t tail[127] = {3, 'a', 'r', 'g'};
  uint8_t fcb1[16];
  uint8_t fcb2[16];
  uint8_t psp[DAZE_DOS_EXEC_PSP_SIZE];
  memset(fcb1, 0x11, sizeof(fcb1));
  memset(fcb2, 0x22, sizeof(fcb2));
  if (!daze_dos_exec_psp_build(0x3000, 0x1000, 0x119b, 0x0050, tail, fcb1, fcb2, psp) ||
      psp[0] != 0xcd || psp[1] != 0x20 || psp[0x0a] != 0x10 || psp[0x0c] != 0x50 ||
      psp[0x16] != 0 || psp[0x17] != 0x10 || psp[0x2c] != 0x9b || psp[0x2d] != 0x11 ||
      memcmp(psp + 0x5c, fcb1, sizeof(fcb1)) != 0 || memcmp(psp + 0x6c, fcb2, sizeof(fcb2)) != 0 ||
      psp[0x80] != 3 || memcmp(psp + 0x81, "arg", 3) != 0 || psp[0x84] != '\r') {
    return 1;
  }
  tail[0] = 127;
  return daze_dos_exec_psp_build(0, 0, 0, 0, tail, fcb1, fcb2, psp) ? 1 : 0;
}
