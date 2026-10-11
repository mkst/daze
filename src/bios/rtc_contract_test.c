#include "rtc.h"

#include <stdio.h>

int main(void) {
  DazeBiosRtcTime reply;
  if (!daze_bios_rtc_time(&reply)) return 1;
  if (reply.cx != 0 || reply.dx != 0 || reply.carry != 0) return 1;
  if (daze_bios_rtc_time(NULL)) return 1;
  puts("BIOS RTC time reply: passed");
  return 0;
}
