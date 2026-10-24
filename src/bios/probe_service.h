#ifndef DAZE_BIOS_PROBE_SERVICE_H
#define DAZE_BIOS_PROBE_SERVICE_H

#include <stdint.h>

typedef enum {
  DAZE_BIOS_PROBE_UNSUPPORTED = 0,
  DAZE_BIOS_PROBE_EQUIPMENT,
  DAZE_BIOS_PROBE_VIDEO_MODE,
  DAZE_BIOS_PROBE_EGA,
  DAZE_BIOS_PROBE_TIMER,
} DazeBiosProbeKind;

enum {
  DAZE_BIOS_PROBE_REG_AX = 1u << 0,
  DAZE_BIOS_PROBE_REG_BX = 1u << 1,
  DAZE_BIOS_PROBE_REG_CX = 1u << 2,
  DAZE_BIOS_PROBE_REG_DX = 1u << 3,
};

/* Handled probes write CF and only the selected low register words. */
typedef struct {
  uint16_t register_write_mask;
  uint16_t ax, bx, cx, dx;
  int carry;
} DazeBiosProbeReply;

DazeBiosProbeKind daze_bios_probe_dispatch(uint8_t interrupt, uint16_t ax, uint16_t bx,
                                           DazeBiosProbeReply *reply);

#endif
