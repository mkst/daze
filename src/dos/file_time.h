#ifndef DAZE_DOS_FILE_TIME_H
#define DAZE_DOS_FILE_TIME_H

#include <stdint.h>

typedef struct {
  /* Invalid handles set carry and AX=6 without changing CX/DX; successful queries
   * preserve AX. */
  int valid;
  uint16_t cx;
  uint16_t dx;
  uint16_t error_ax;
  int carry;
} DazeDosFileTimeReply;

/* Host descriptors only establish handle validity; timestamps remain fixed at 2000-01-01
 * 00:00:00. */
int daze_dos_file_time_reply(int handle_valid, DazeDosFileTimeReply *reply);

#endif
