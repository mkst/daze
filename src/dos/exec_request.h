#ifndef DAZE_DOS_EXEC_REQUEST_H
#define DAZE_DOS_EXEC_REQUEST_H

#include <stdint.h>

typedef struct {
  uint16_t environment_segment;
  uint16_t tail_offset, tail_segment;
  uint16_t fcb1_offset, fcb1_segment;
  uint16_t fcb2_offset, fcb2_segment;
} DazeDosExecRequest;

int daze_dos_exec_request_decode(uint8_t mode, int child_active, const uint8_t parameter[14],
                                 const uint8_t tail[127], DazeDosExecRequest *result);

#endif
