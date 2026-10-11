#include "exec_request.h"

#include <stddef.h>

#include "byte_order.h"

int daze_dos_exec_request_decode(uint8_t mode, int child_active, const uint8_t parameter[14],
                                 const uint8_t tail[127], DazeDosExecRequest *result) {
  if (mode != 0 || child_active || parameter == NULL || tail == NULL || result == NULL ||
      tail[0] > 126)
    return 0;
  *result = (DazeDosExecRequest){.environment_segment = daze_read_u16(parameter),
                                 .tail_offset = daze_read_u16(parameter + 2),
                                 .tail_segment = daze_read_u16(parameter + 4),
                                 .fcb1_offset = daze_read_u16(parameter + 6),
                                 .fcb1_segment = daze_read_u16(parameter + 8),
                                 .fcb2_offset = daze_read_u16(parameter + 10),
                                 .fcb2_segment = daze_read_u16(parameter + 12)};
  return 1;
}
