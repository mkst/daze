#ifndef DAZE_DPMI_EXCEPTION_FRAME_H
#define DAZE_DPMI_EXCEPTION_FRAME_H

#include <stdint.h>

enum { DAZE_DPMI_EXCEPTION_FRAME_SIZE = 16 };

/* DPMI 0.9 legacy 16-bit frame consumed by DPMILOAD. Fields are serialized
 * as little-endian words in declaration order, not by copying the struct. */
typedef struct {
  uint16_t return_ip;
  uint16_t return_cs;
  uint16_t error_code;
  uint16_t fault_ip;
  uint16_t fault_cs;
  uint16_t flags;
  uint16_t stack_pointer;
  uint16_t stack_segment;
} DazeDpmiExceptionFrame;

/* Placement is descriptor base + entry SP. Guest range bounds are inclusive
 * linear addresses covering the caller's write-back region. */
typedef struct {
  DazeDpmiExceptionFrame frame;
  uint32_t locked_stack_base;
  uint16_t locked_stack_sp;
  uint32_t guest_range_base;
  uint32_t guest_range_limit;
} DazeDpmiExceptionFrameInput;

/* Builds 16 wire bytes and their linear address; does not write guest memory.
 * Returns 1 only for non-null inputs/outputs, a non-wrapping address, and a
 * frame wholly inside the supplied range. Failure leaves both outputs unchanged. */
int daze_dpmi_exception_frame_build(const DazeDpmiExceptionFrameInput *input,
                                    uint32_t *frame_linear, uint8_t *frame);

#endif
