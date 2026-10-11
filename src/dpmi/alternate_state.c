#include "alternate_state.h"

#include <stddef.h>
#include <string.h>

#include "byte_order.h"
enum {
  k_offset_eax = 0x00,
  k_offset_ebx = 0x04,
  k_offset_ecx = 0x08,
  k_offset_edx = 0x0c,
  k_offset_esi = 0x10,
  k_offset_edi = 0x14,
  k_offset_ebp = 0x18,
  k_offset_esp = 0x1c,
  k_offset_eip = 0x20,
  k_offset_eflags = 0x24,
  k_offset_cs = 0x28,
  k_offset_ds = 0x2a,
  k_offset_es = 0x2c,
  k_offset_fs = 0x2e,
  k_offset_gs = 0x30,
  k_offset_ss = 0x32,
  k_offset_reserved = 0x34,
};

int daze_dpmi_alternate_state_valid(const DpmiAlternateState *state) {
  if (state == NULL || state->eip > UINT16_MAX || state->esp > UINT16_MAX || state->cs == 0 ||
      state->ds == 0 || state->ss == 0) {
    return 0;
  }
  for (size_t index = 0; index < sizeof(state->reserved); ++index) {
    if (state->reserved[index] != 0) return 0;
  }
  return 1;
}

int daze_dpmi_alternate_state_pack(const DpmiAlternateState *state,
                                   uint8_t image[DAZE_DPMI_ALTERNATE_STATE_SIZE]) {
  if (state == NULL || image == NULL) return 0;
  daze_write_u32(image + k_offset_eax, state->eax);
  daze_write_u32(image + k_offset_ebx, state->ebx);
  daze_write_u32(image + k_offset_ecx, state->ecx);
  daze_write_u32(image + k_offset_edx, state->edx);
  daze_write_u32(image + k_offset_esi, state->esi);
  daze_write_u32(image + k_offset_edi, state->edi);
  daze_write_u32(image + k_offset_ebp, state->ebp);
  daze_write_u32(image + k_offset_esp, state->esp);
  daze_write_u32(image + k_offset_eip, state->eip);
  daze_write_u32(image + k_offset_eflags, state->eflags);
  daze_write_u16(image + k_offset_cs, state->cs);
  daze_write_u16(image + k_offset_ds, state->ds);
  daze_write_u16(image + k_offset_es, state->es);
  daze_write_u16(image + k_offset_fs, state->fs);
  daze_write_u16(image + k_offset_gs, state->gs);
  daze_write_u16(image + k_offset_ss, state->ss);
  for (size_t index = 0; index < sizeof(state->reserved); ++index) {
    image[k_offset_reserved + index] = state->reserved[index];
  }
  return 1;
}

int daze_dpmi_alternate_state_unpack(const uint8_t image[DAZE_DPMI_ALTERNATE_STATE_SIZE],
                                     DpmiAlternateState *state) {
  if (image == NULL || state == NULL) return 0;
  DpmiAlternateState decoded = {0};
  decoded.eax = daze_read_u32(image + k_offset_eax);
  decoded.ebx = daze_read_u32(image + k_offset_ebx);
  decoded.ecx = daze_read_u32(image + k_offset_ecx);
  decoded.edx = daze_read_u32(image + k_offset_edx);
  decoded.esi = daze_read_u32(image + k_offset_esi);
  decoded.edi = daze_read_u32(image + k_offset_edi);
  decoded.ebp = daze_read_u32(image + k_offset_ebp);
  decoded.esp = daze_read_u32(image + k_offset_esp);
  decoded.eip = daze_read_u32(image + k_offset_eip);
  decoded.eflags = daze_read_u32(image + k_offset_eflags);
  decoded.cs = daze_read_u16(image + k_offset_cs);
  decoded.ds = daze_read_u16(image + k_offset_ds);
  decoded.es = daze_read_u16(image + k_offset_es);
  decoded.fs = daze_read_u16(image + k_offset_fs);
  decoded.gs = daze_read_u16(image + k_offset_gs);
  decoded.ss = daze_read_u16(image + k_offset_ss);
  memcpy(decoded.reserved, image + k_offset_reserved, sizeof(decoded.reserved));
  if (!daze_dpmi_alternate_state_valid(&decoded)) return 0;
  *state = decoded;
  return 1;
}
