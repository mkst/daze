#ifndef DAZE_DOS_COUNTRY_H
#define DAZE_DOS_COUNTRY_H

#include <stdint.h>

/* INT 21h/AH=38h writes the 24-byte country-information prefix; the 10
 * reserved tail bytes stay caller-owned and are never touched. */
#define DAZE_DOS_COUNTRY_TABLE_SIZE 24u
#define DAZE_DOS_COUNTRY_CODE_USA 1u

extern const uint8_t daze_dos_country_usa[DAZE_DOS_COUNTRY_TABLE_SIZE];

#endif
