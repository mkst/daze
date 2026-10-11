#include "rm_frame.h"

#include "kvm_bytes.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  /* Frame built from the observed CC1PSX 2.7.2 0301h request: ES=0x10 with
   * base 0x1fe20, DI=0x0c74, target 1000:2189, stack 1fe2:feb0. */
  uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE];
  memset(frame, 0xa5, sizeof(frame));
  daze_write_u32(frame + DAZE_DPMI_RM_EDI, 0x00000c74u);
  daze_write_u32(frame + DAZE_DPMI_RM_EBX, 0x11223344u);
  daze_write_u16(frame + DAZE_DPMI_RM_IP, 0x2189);
  daze_write_u16(frame + DAZE_DPMI_RM_CS, 0x1000);
  daze_write_u16(frame + DAZE_DPMI_RM_SP, 0xfeb0);
  daze_write_u16(frame + DAZE_DPMI_RM_SS, 0x1fe2);
  daze_write_u16(frame + DAZE_DPMI_RM_ES, 0x1234);
  daze_write_u16(frame + DAZE_DPMI_RM_DS, 0x5678);
  daze_write_u16(frame + DAZE_DPMI_RM_FS, 0x0000);
  daze_write_u16(frame + DAZE_DPMI_RM_GS, 0x0000);
  daze_write_u16(frame + DAZE_DPMI_RM_FLAGS, 0xf002);
  DazeDpmiRmProcedure procedure;
  const int parse = daze_dpmi_rm_frame_parse(frame, 0x1fe20, 0x0c74, 0, 0, 0, &procedure);
  const int parsed = parse && procedure.target_cs == 0x1000 && procedure.target_ip == 0x2189 &&
                     procedure.frame_ss == 0x1fe2 && procedure.frame_sp == 0xfeb0 &&
                     procedure.procedure_sp == 0xfeac && procedure.frame_address == 0x20a94 &&
                     procedure.stack_address == 0x2fccc;
  const int rejects = !daze_dpmi_rm_frame_parse(frame, 0x1fe20, 0x0c74, 1, 0, 0, &procedure) &&
                      !daze_dpmi_rm_frame_parse(frame, 0x1fe20, 0x0c74, 0, 0x0100, 0, &procedure) &&
                      !daze_dpmi_rm_frame_parse(frame, 0x1fe20, 0x0c74, 0, 0, 1, &procedure) &&
                      !daze_dpmi_rm_frame_parse(frame, 0x1fe20, 0x0c74, 0, 0, 0, NULL);
  uint8_t bcc_frame[DAZE_DPMI_RM_FRAME_SIZE] = {0};
  daze_write_u16(bcc_frame + DAZE_DPMI_RM_CS, 0x1619);
  if (!daze_dpmi_rm_frame_parse(bcc_frame, 0x14850, 0x1530, 2, 0, 0, &procedure) ||
      procedure.frame_ss != 0x0040 || procedure.procedure_sp != 0x0be0 ||
      procedure.stack_address != 0x0fe0 || procedure.parameter_bytes != 4 ||
      procedure.frame_address != 0x15d80 || daze_read_u16(bcc_frame + DAZE_DPMI_RM_SS) != 0)
    return 1;
  uint8_t host_stack_frame[DAZE_DPMI_RM_FRAME_SIZE];
  memset(host_stack_frame, 0, sizeof(host_stack_frame));
  daze_write_u16(host_stack_frame + DAZE_DPMI_RM_SP, 0x0004);
  daze_write_u16(host_stack_frame + DAZE_DPMI_RM_SS, 0x0040);
  const int host_stack =
    daze_dpmi_rm_frame_parse(host_stack_frame, 0x1fe20, 0x0c74, 0, 0, 0, &procedure);
  const int null_frames = daze_dpmi_rm_frame_parse(NULL, 0x1fe20, 0x0c74, 0, 0, 0, &procedure) == 0;
  daze_write_u16(frame + DAZE_DPMI_RM_SP, 0x0000);
  const int zero_sp = daze_dpmi_rm_frame_parse(frame, 0x1fe20, 0x0c74, 0, 0, 0, &procedure) == 0;
  daze_write_u16(frame + DAZE_DPMI_RM_SS, 0x0000);
  const int zero_ss = daze_dpmi_rm_frame_parse(frame, 0x1fe20, 0x0c74, 0, 0, 0, &procedure) == 0;
  const int overflow =
    daze_dpmi_rm_frame_parse(frame, UINT32_MAX - 0x0c74, 0x0c74, 0, 0, 0, &procedure) == 0;
  daze_write_u16(frame + DAZE_DPMI_RM_SS, 0x1fe2);
  daze_write_u16(frame + DAZE_DPMI_RM_SP, 0xfeb0);

  uint8_t far_return[4] = {0};
  const int far_ok = daze_dpmi_rm_far_return(far_return) && far_return[0] == 0x00 &&
                     far_return[1] == 0x00 && far_return[2] == 0x30 && far_return[3] == 0x02 &&
                     daze_dpmi_rm_far_return(NULL) == 0;

  const DazeDpmiRmWriteBack image = {
    .edi = 0x11111111u,
    .esi = 0x22222222u,
    .ebp = 0x33333333u,
    .ebx = 0x44444444u,
    .edx = 0x55555555u,
    .ecx = 0x66666666u,
    .eax = 0x77777777u,
    .flags = 0xf246,
    .es = 0x1111,
    .ds = 0x2222,
    .fs = 0x3333,
    .gs = 0x4444,
  };
  uint8_t written[DAZE_DPMI_RM_FRAME_SIZE];
  memcpy(written, frame, sizeof(written));
  daze_dpmi_rm_frame_write_back(written, &image);
  int write_back = daze_read_u32(written + DAZE_DPMI_RM_EDI) == 0x11111111u &&
                   daze_read_u32(written + DAZE_DPMI_RM_ESI) == 0x22222222u &&
                   daze_read_u32(written + DAZE_DPMI_RM_EBP) == 0x33333333u &&
                   daze_read_u32(written + DAZE_DPMI_RM_EBX) == 0x44444444u &&
                   daze_read_u32(written + DAZE_DPMI_RM_EDX) == 0x55555555u &&
                   daze_read_u32(written + DAZE_DPMI_RM_ECX) == 0x66666666u &&
                   daze_read_u32(written + DAZE_DPMI_RM_EAX) == 0x77777777u &&
                   daze_read_u16(written + DAZE_DPMI_RM_FLAGS) == 0xf246 &&
                   daze_read_u16(written + DAZE_DPMI_RM_ES) == 0x1111 &&
                   daze_read_u16(written + DAZE_DPMI_RM_DS) == 0x2222 &&
                   daze_read_u16(written + DAZE_DPMI_RM_FS) == 0x3333 &&
                   daze_read_u16(written + DAZE_DPMI_RM_GS) == 0x4444 &&
                   daze_read_u16(written + DAZE_DPMI_RM_IP) == 0x2189 &&
                   daze_read_u16(written + DAZE_DPMI_RM_CS) == 0x1000 &&
                   daze_read_u16(written + DAZE_DPMI_RM_SP) == 0xfeb0 &&
                   daze_read_u16(written + DAZE_DPMI_RM_SS) == 0x1fe2;
  daze_dpmi_rm_frame_write_back(written, NULL);
  const int write_back_null = daze_read_u16(written + DAZE_DPMI_RM_ES) == 0x1111;
  if (!parsed || !rejects || !host_stack || !null_frames || !zero_sp || !zero_ss || !overflow ||
      !far_ok || !write_back || !write_back_null) {
    fprintf(stderr,
            "DPMI RM frame contract failed parsed=%d rejects=%d host_stack=%d null_frames=%d "
            "zero_sp=%d zero_ss=%d overflow=%d far_ok=%d write_back=%d null=%d\n",
            parsed, rejects, host_stack, null_frames, zero_sp, zero_ss, overflow, far_ok,
            write_back, write_back_null);
    return 1;
  }
  return 0;
}
