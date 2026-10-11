#include "rtc.h"

#include <stddef.h>

int daze_bios_rtc_time(DazeBiosRtcTime *reply) {
  if (reply == NULL) return 0;
  /* Fixed midnight identity, independent of the host clock. */
  *reply = (DazeBiosRtcTime){
    .cx = 0,
    .dx = 0,
    .carry = 0,
  };
  return 1;
}
