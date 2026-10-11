#ifndef DAZE_BIOS_RTC_H
#define DAZE_BIOS_RTC_H

#include <stdint.h>

/* Deterministic midnight in BCD, independent of the host clock. */
typedef struct {
  uint16_t cx, dx;
  int carry;
} DazeBiosRtcTime;

int daze_bios_rtc_time(DazeBiosRtcTime *reply);

#endif
