#include "timer.h"

#include <stdio.h>

int main(void) {
  DazeBiosTimerTick reply;
  if (!daze_bios_timer_ticks(&reply)) return 1;
  if (reply.ax != 0 || reply.cx != 0 || reply.dx != 0 || reply.carry != 0) return 1;
  if (daze_bios_timer_ticks(NULL)) return 1;
  puts("BIOS timer tick reply: passed");
  return 0;
}
