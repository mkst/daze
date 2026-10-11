#include "exception_frame.h"

#include <stddef.h>

#include "byte_order.h"

int daze_dpmi_exception_frame_build(const DazeDpmiExceptionFrameInput *input,
                                    uint32_t *frame_linear, uint8_t *frame) {
  if (input == NULL || frame_linear == NULL || frame == NULL) return 0;
  if (input->guest_range_base > input->guest_range_limit) return 0;
  if (input->guest_range_limit < (uint32_t)(DAZE_DPMI_EXCEPTION_FRAME_SIZE - 1)) return 0;
  const uint64_t address = (uint64_t)input->locked_stack_base + input->locked_stack_sp;
  if (address > 0xffffffffu) return 0;
  if (address < input->guest_range_base) return 0;
  if (address > (uint64_t)input->guest_range_limit - (DAZE_DPMI_EXCEPTION_FRAME_SIZE - 1)) return 0;

  uint8_t staged[DAZE_DPMI_EXCEPTION_FRAME_SIZE];
  daze_write_u16(staged, input->frame.return_ip);
  daze_write_u16(staged + 2, input->frame.return_cs);
  daze_write_u16(staged + 4, input->frame.error_code);
  daze_write_u16(staged + 6, input->frame.fault_ip);
  daze_write_u16(staged + 8, input->frame.fault_cs);
  daze_write_u16(staged + 10, input->frame.flags);
  daze_write_u16(staged + 12, input->frame.stack_pointer);
  daze_write_u16(staged + 14, input->frame.stack_segment);
  for (size_t index = 0; index < DAZE_DPMI_EXCEPTION_FRAME_SIZE; ++index)
    frame[index] = staged[index];
  *frame_linear = (uint32_t)address;
  return 1;
}
