#ifndef DAZE_BIOS_TIMER_H
#define DAZE_BIOS_TIMER_H

#include <stdint.h>

/* Shared INT 1Ah timer reply: deterministic midnight ticks and no rollover. */
typedef struct {
  uint16_t ax, cx, dx;
  int carry;
} DazeBiosTimerTick;

/* Returns 0 only for a null output pointer. */
int daze_bios_timer_ticks(DazeBiosTimerTick *reply);

#endif
