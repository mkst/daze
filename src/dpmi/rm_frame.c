#include "rm_frame.h"

#include "byte_order.h"

#include <limits.h>
#include <string.h>

int daze_dpmi_rm_frame_parse(const uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE], uint32_t es_base,
                             uint32_t offset, uint16_t cx, uint16_t bx, int code_is_32bit,
                             DazeDpmiRmProcedure *output) {
  if (frame == NULL || output == NULL) return 0;
  if ((cx != 0 && cx != 2) || (bx >> 8) != 0 || code_is_32bit) return 0;
  if (es_base > UINT32_MAX - offset || es_base + offset > UINT32_MAX - DAZE_DPMI_RM_FRAME_SIZE) {
    return 0;
  }
  uint16_t frame_ss = daze_read_u16(frame + DAZE_DPMI_RM_SS);
  uint16_t frame_sp = daze_read_u16(frame + DAZE_DPMI_RM_SP);
  /* The supported two-word form uses the host return stack; preserve caller frame bytes
   * on write-back. */
  if (frame_ss == 0 && frame_sp == 0 && cx == 2) {
    frame_ss = 0x0040;
    frame_sp = 0x0be4;
  }
  if (frame_ss == 0 || frame_sp < 4) return 0;
  const uint32_t stack_top = ((uint32_t)frame_ss << 4) + frame_sp;
  if (stack_top < 4 || stack_top > UINT32_MAX) return 0;
  *output = (DazeDpmiRmProcedure){
    .target_cs = daze_read_u16(frame + DAZE_DPMI_RM_CS),
    .target_ip = daze_read_u16(frame + DAZE_DPMI_RM_IP),
    .frame_ss = frame_ss,
    .frame_sp = frame_sp,
    .procedure_sp = (uint16_t)(frame_sp - 4),
    .frame_address = es_base + offset,
    .stack_address = stack_top - 4,
    .parameter_bytes = (uint16_t)(cx * 2u),
  };
  return 1;
}

int daze_dpmi_rm_far_return(uint8_t bytes[4]) {
  if (bytes == NULL) return 0;
  bytes[0] = (uint8_t)DAZE_DPMI_RM_RETURN_IP;
  bytes[1] = (uint8_t)(DAZE_DPMI_RM_RETURN_IP >> 8);
  bytes[2] = (uint8_t)DAZE_DPMI_RM_RETURN_CS;
  bytes[3] = (uint8_t)(DAZE_DPMI_RM_RETURN_CS >> 8);
  return 1;
}

void daze_dpmi_rm_frame_write_back(uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE],
                                   const DazeDpmiRmWriteBack *registers) {
  if (frame == NULL || registers == NULL) return;
  daze_write_u32(frame + DAZE_DPMI_RM_EDI, registers->edi);
  daze_write_u32(frame + DAZE_DPMI_RM_ESI, registers->esi);
  daze_write_u32(frame + DAZE_DPMI_RM_EBP, registers->ebp);
  daze_write_u32(frame + DAZE_DPMI_RM_EBX, registers->ebx);
  daze_write_u32(frame + DAZE_DPMI_RM_EDX, registers->edx);
  daze_write_u32(frame + DAZE_DPMI_RM_ECX, registers->ecx);
  daze_write_u32(frame + DAZE_DPMI_RM_EAX, registers->eax);
  daze_write_u16(frame + DAZE_DPMI_RM_FLAGS, registers->flags);
  daze_write_u16(frame + DAZE_DPMI_RM_ES, registers->es);
  daze_write_u16(frame + DAZE_DPMI_RM_DS, registers->ds);
  daze_write_u16(frame + DAZE_DPMI_RM_FS, registers->fs);
  daze_write_u16(frame + DAZE_DPMI_RM_GS, registers->gs);
}
