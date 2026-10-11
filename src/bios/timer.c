#include "timer.h"

#include <stddef.h>

int daze_bios_timer_ticks(DazeBiosTimerTick *reply) {
  if (reply == NULL) return 0;
  *reply = (DazeBiosTimerTick){
    .ax = 0,
    .cx = 0,
    .dx = 0,
    .carry = 0,
  };
  return 1;
}
