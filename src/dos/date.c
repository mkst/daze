#include "date.h"

#include <time.h>

int daze_dos_date_pack(DazeDosDate *date, const struct tm *local) {
  if (date == NULL) return 1;
  if (local == NULL) {
    date->year = 2000;
    date->month = 1;
    date->day = 1;
    date->weekday = 6;
    return 1;
  }
  date->year = (uint16_t)(local->tm_year + 1900);
  date->month = (uint8_t)(local->tm_mon + 1);
  date->day = (uint8_t)local->tm_mday;
  date->weekday = (uint8_t)local->tm_wday;
  return 1;
}

int daze_dos_date_get(DazeDosDate *date) {
  if (date == NULL) return 0;
  const time_t now = time(NULL);
  struct tm local = {0};
  if (now != (time_t)-1 && localtime_r(&now, &local) != NULL) {
    daze_dos_date_pack(date, &local);
    return 1;
  }
  daze_dos_date_pack(date, NULL);
  return 0;
}
