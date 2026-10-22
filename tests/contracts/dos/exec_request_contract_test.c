#include "exec_request.h"

#include <stdio.h>

int main(void) {
  const uint8_t parameter[14] = {0x9b, 0x11, 0xce, 0x03, 0x5b, 0x11, 0x4e,
                                 0x32, 0x5b, 0x11, 0x5e, 0x32, 0x5b, 0x11};
  uint8_t tail[127] = {37};
  DazeDosExecRequest request;
  if (!daze_dos_exec_request_decode(0, 0, parameter, tail, &request) ||
      request.environment_segment != 0x119b || request.tail_offset != 0x03ce ||
      request.tail_segment != 0x115b || request.fcb1_offset != 0x324e ||
      request.fcb1_segment != 0x115b || request.fcb2_offset != 0x325e ||
      request.fcb2_segment != 0x115b)
    return 1;
  tail[0] = 127;
  if (daze_dos_exec_request_decode(0, 0, parameter, tail, &request) ||
      daze_dos_exec_request_decode(1, 0, parameter, tail, &request) ||
      daze_dos_exec_request_decode(0, 1, parameter, tail, &request)) {
    fprintf(stderr, "invalid EXEC request accepted\n");
    return 1;
  }
  return 0;
}
