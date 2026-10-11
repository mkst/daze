#ifndef DAZE_DOS_FCB_H
#define DAZE_DOS_FCB_H

#include <stddef.h>
#include <stdint.h>

/* The input must be bounded and delimiter-terminated. Invalid drives return 0xff with
 * unspecified FCB and consumed count. */
int daze_dos_fcb_parse(const uint8_t *input, size_t input_size, uint8_t control, uint8_t fcb[16],
                       size_t *consumed, uint8_t *result);

#endif
