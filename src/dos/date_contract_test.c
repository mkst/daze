#include "date.h"

#include <stdio.h>
#include <time.h>

static int host_date_is_plausible(const DazeDosDate *date) {
  if (date->year < 1970 || date->year > 2200) {
    fprintf(stderr, "dos date: unexpected year %u\n", (unsigned)date->year);
    return 0;
  }
  if (date->month < 1 || date->month > 12) {
    fprintf(stderr, "dos date: unexpected month %u\n", (unsigned)date->month);
    return 0;
  }
  if (date->day < 1 || date->day > 31) {
    fprintf(stderr, "dos date: unexpected day %u\n", (unsigned)date->day);
    return 0;
  }
  if (date->weekday > 6) {
    fprintf(stderr, "dos date: unexpected weekday %u\n", (unsigned)date->weekday);
    return 0;
  }
  return 1;
}

int main(void) {
  const struct tm probe = {.tm_year = 100, .tm_mon = 5, .tm_mday = 15, .tm_wday = 4};
  DazeDosDate date = {0};
  if (!daze_dos_date_pack(NULL, &probe) || !daze_dos_date_pack(NULL, NULL) ||
      daze_dos_date_get(NULL))
    return 1;
  if (!daze_dos_date_pack(&date, &probe) || date.year != 2000 || date.month != 6 ||
      date.day != 15 || date.weekday != 4) {
    fprintf(stderr, "dos date: probe pack year=%u month=%u day=%u weekday=%u\n",
            (unsigned)date.year, (unsigned)date.month, (unsigned)date.day, (unsigned)date.weekday);
    return 1;
  }
  date = (DazeDosDate){0};
  if (!daze_dos_date_pack(&date, NULL) || date.year != 2000 || date.month != 1 || date.day != 1 ||
      date.weekday != 6) {
    fprintf(stderr, "dos date: fallback pack year=%u month=%u day=%u weekday=%u\n",
            (unsigned)date.year, (unsigned)date.month, (unsigned)date.day, (unsigned)date.weekday);
    return 1;
  }
  fprintf(stderr, "dos date: fallback packs Saturday 2000-01-01\n");
  date = (DazeDosDate){0};
  if (!daze_dos_date_get(&date)) {
    fprintf(stderr, "dos date: host local date unexpectedly unavailable\n");
    return 1;
  }
  if (!host_date_is_plausible(&date)) return 1;
  fprintf(stderr, "dos date: host local %04u-%02u-%02u (weekday %u)\n", (unsigned)date.year,
          (unsigned)date.month, (unsigned)date.day, (unsigned)date.weekday);
  return 0;
}
