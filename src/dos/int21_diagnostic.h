#ifndef DAZE_DOS_INT21_DIAGNOSTIC_H
#define DAZE_DOS_INT21_DIAGNOSTIC_H

#include <stdint.h>
#include <stdio.h>

#include "int21_service.h"

static inline void daze_dos_int21_log_unsupported(const DazeDosInt21Request *request, uint16_t cs,
                                                  uint16_t ip) {
  fprintf(stderr,
          "unsupported DOS 21h function %02xh (AX=%04x BX=%04x CX=%04x DX=%04x) "
          "at CS:IP=%04x:%04x DS=%04x\n",
          (uint8_t)(request->ax >> 8), request->ax, request->bx, request->cx, request->dx, cs, ip,
          request->ds);
}

#endif
