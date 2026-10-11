#ifndef DAZE_DOS_DATE_H
#define DAZE_DOS_DATE_H

#include <stdint.h>
#include <time.h>

typedef struct {
  uint16_t year;
  uint8_t month;
  uint8_t day;
  uint8_t weekday;
} DazeDosDate;

/* Use the host's local calendar; conversion failure falls back to Saturday 2000-01-01. */
int daze_dos_date_get(DazeDosDate *date);

int daze_dos_date_pack(DazeDosDate *date, const struct tm *local);

#endif
