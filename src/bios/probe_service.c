#include "probe_service.h"

#include "interrupt_vector.h"
#include "timer.h"

#include <stddef.h>

DazeBiosProbeKind daze_bios_probe_dispatch(uint8_t interrupt, uint16_t ax, uint16_t bx,
                                           DazeBiosProbeReply *reply) {
  if (reply == NULL) return DAZE_BIOS_PROBE_UNSUPPORTED;
  *reply = (DazeBiosProbeReply){0};
  if (interrupt == DAZE_INT_BIOS_EQUIPMENT) {
    /* This identity admits text-mode probes without advertising peripherals. */
    reply->register_write_mask = DAZE_BIOS_PROBE_REG_AX;
    reply->ax = 0x0020;
    return DAZE_BIOS_PROBE_EQUIPMENT;
  }
  if (interrupt == DAZE_INT_BIOS_VIDEO && (ax >> 8) == 0x0f) {
    reply->register_write_mask = DAZE_BIOS_PROBE_REG_AX | DAZE_BIOS_PROBE_REG_BX;
    reply->ax = 0x5003; /* AH=80 columns, AL=mode 3. */
    reply->bx = (uint16_t)(bx & 0x00ffu);
    return DAZE_BIOS_PROBE_VIDEO_MODE;
  }
  if (interrupt == DAZE_INT_BIOS_VIDEO && ax == 0x1200 && (bx & 0x00ffu) == 0x10) {
    /* Extenders use this color/256 KiB EGA identity to avoid their CGA path;
     * it does not expose graphics memory or mode-setting operations. */
    reply->register_write_mask = DAZE_BIOS_PROBE_REG_BX | DAZE_BIOS_PROBE_REG_CX;
    reply->bx = 0x0003;
    reply->cx = 0x0001;
    return DAZE_BIOS_PROBE_EGA;
  }
  if (interrupt == DAZE_INT_BIOS_TIME && (ax >> 8) == 0x00) {
    DazeBiosTimerTick tick;
    (void)daze_bios_timer_ticks(&tick);
    reply->register_write_mask =
      DAZE_BIOS_PROBE_REG_AX | DAZE_BIOS_PROBE_REG_CX | DAZE_BIOS_PROBE_REG_DX;
    reply->ax = tick.ax;
    reply->cx = tick.cx;
    reply->dx = tick.dx;
    reply->carry = tick.carry;
    return DAZE_BIOS_PROBE_TIMER;
  }
  return DAZE_BIOS_PROBE_UNSUPPORTED;
}
