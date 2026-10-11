#include "exception_frame.h"

#include <stdio.h>
#include <string.h>

/* Every byte distinct, so a rejected build that writes anything is visible. */
static const uint8_t k_sentinel[DAZE_DPMI_EXCEPTION_FRAME_SIZE] = {
  0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
};

static const uint32_t k_sentinel_linear = 0x12345678u;

static int writes_exactly(const DazeDpmiExceptionFrameInput *input, uint32_t expected_linear,
                          const uint8_t expected[DAZE_DPMI_EXCEPTION_FRAME_SIZE]) {
  uint8_t frame[DAZE_DPMI_EXCEPTION_FRAME_SIZE];
  uint32_t frame_linear = 0;
  memset(frame, 0xa5, sizeof(frame));
  if (!daze_dpmi_exception_frame_build(input, &frame_linear, frame)) return 0;
  if (frame_linear != expected_linear) return 0;
  return memcmp(frame, expected, DAZE_DPMI_EXCEPTION_FRAME_SIZE) == 0;
}

/* A rejected build leaves both outputs byte-identical to their pre-call state. */
static int rejected_unchanged(const DazeDpmiExceptionFrameInput *input) {
  uint8_t frame[DAZE_DPMI_EXCEPTION_FRAME_SIZE];
  uint32_t frame_linear = k_sentinel_linear;
  memcpy(frame, k_sentinel, sizeof(frame));
  if (daze_dpmi_exception_frame_build(input, &frame_linear, frame)) return 0;
  if (memcmp(frame, k_sentinel, sizeof(frame)) != 0) return 0;
  return frame_linear == k_sentinel_linear;
}

int main(void) {
  int pass = 1;

  /* Measured BCC 3.1 #NP: 00b4:015a calls non-present LDT selector 00d4,
   * with SS:SP=0124:ffb0. Return IP/CS are synthetic landing-pad values.
   * Flags are opaque wire data: even reserved bits must be copied verbatim. */
  DazeDpmiExceptionFrameInput observed;
  observed.frame.return_ip = 0x0400u;
  observed.frame.return_cs = 0x0030u;
  observed.frame.error_code = 0x00d4u;
  observed.frame.fault_ip = 0x015au;
  observed.frame.fault_cs = 0x00b4u;
  observed.frame.flags = 0xffffu;
  observed.frame.stack_pointer = 0xffb0u;
  observed.frame.stack_segment = 0x0124u;
  observed.locked_stack_base = 0x007d0000u;
  observed.locked_stack_sp = 0x0ff0u;
  observed.guest_range_base = 0x007d0000u;
  observed.guest_range_limit = 0x007d0fffu;
  const uint8_t observed_frame[DAZE_DPMI_EXCEPTION_FRAME_SIZE] = {
    0x00, 0x04, 0x30, 0x00, 0xd4, 0x00, 0x5a, 0x01, 0xb4, 0x00, 0xff, 0xff, 0xb0, 0xff, 0x24, 0x01,
  };
  pass = pass && writes_exactly(&observed, 0x007d0ff0u, observed_frame);

  /* A fault without a defined error code retains a zero error word; the builder
   * must not invent one. Placement uses a dynamic client allocation. */
  DazeDpmiExceptionFrameInput no_error_code = observed;
  no_error_code.frame.error_code = 0x0000u;
  no_error_code.frame.fault_cs = 0x0008u;
  no_error_code.frame.stack_pointer = 0x0fe0u;
  no_error_code.frame.stack_segment = 0x0040u;
  no_error_code.locked_stack_base = 0x00050000u;
  no_error_code.locked_stack_sp = 0x0ff0u;
  no_error_code.guest_range_base = 0x00050000u;
  no_error_code.guest_range_limit = 0x00050fffu;
  const uint8_t no_error_code_frame[DAZE_DPMI_EXCEPTION_FRAME_SIZE] = {
    0x00, 0x04, 0x30, 0x00, 0x00, 0x00, 0x5a, 0x01, 0x08, 0x00, 0xff, 0xff, 0xe0, 0x0f, 0x40, 0x00,
  };
  pass = pass && writes_exactly(&no_error_code, 0x00050ff0u, no_error_code_frame);

  uint8_t frame[DAZE_DPMI_EXCEPTION_FRAME_SIZE];
  uint32_t frame_linear = 0;
  pass = pass && !daze_dpmi_exception_frame_build(NULL, &frame_linear, frame) &&
         !daze_dpmi_exception_frame_build(&observed, NULL, frame) &&
         !daze_dpmi_exception_frame_build(&observed, &frame_linear, NULL) &&
         rejected_unchanged(NULL);

  /* Address overflow: 0xfffffff0 + 0x0010 does not fit 32 bits. */
  DazeDpmiExceptionFrameInput overflow = observed;
  overflow.locked_stack_base = 0xfffffff0u;
  overflow.locked_stack_sp = 0x0010u;
  pass = pass && rejected_unchanged(&overflow);

  DazeDpmiExceptionFrameInput underflow = observed;
  underflow.locked_stack_base = 0x007cfff0u;
  underflow.locked_stack_sp = 0x0000u;
  pass = pass && rejected_unchanged(&underflow);

  DazeDpmiExceptionFrameInput overrun = observed;
  overrun.guest_range_limit = 0x007d0ffeu;
  pass = pass && rejected_unchanged(&overrun);

  DazeDpmiExceptionFrameInput inverted = observed;
  inverted.guest_range_base = 0x007d0fffu;
  inverted.guest_range_limit = 0x007d0000u;
  DazeDpmiExceptionFrameInput narrow = observed;
  narrow.guest_range_base = 0x00000000u;
  narrow.guest_range_limit = 0x0000000eu;
  pass = pass && rejected_unchanged(&inverted) && rejected_unchanged(&narrow);

  /* The frame's last byte landing exactly on guest_range_limit is accepted. */
  DazeDpmiExceptionFrameInput exact = observed;
  exact.guest_range_base = 0x007d0ff0u;
  exact.guest_range_limit = 0x007d0fffu;
  pass = pass && writes_exactly(&exact, 0x007d0ff0u, observed_frame);

  printf("exception-frame-contract: %s (%d checks)\n", pass ? "passed" : "FAILED", 12);
  return pass ? 0 : 1;
}
