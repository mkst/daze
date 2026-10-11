#ifndef DAZE_DOS_FILE_ATTRS_H
#define DAZE_DOS_FILE_ATTRS_H

#include "dosfs.h"

#include <stdint.h>

typedef struct {
  uint16_t attributes; /* 0x10 directory, 0x20 archive/normal when served */
  uint16_t dos_error;  /* valid only when successful == 0 */
  int successful;      /* 1 -> reply CX, CF clear; 0 -> reply AX=dos_error, CF set */
} DazeDosFileAttrs;

int daze_dos_file_attrs_get(const DazeDosfsMounts *mounts, const char *guest_path,
                            DazeDosFileAttrs *result);

#endif
