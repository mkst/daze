#include "country.h"

/* Fixed USA table keeps guest runs deterministic: no host locale leaks into
 * the guest. Layout matches the DOS country-information prefix evidenced
 * against the DOSEMU2 oracle; the far case-map pointer stays null because the
 * oracle's host-kernel address is meaningless here and no evidenced caller
 * invokes it. */
const uint8_t daze_dos_country_usa[DAZE_DOS_COUNTRY_TABLE_SIZE] = {
  0x00, 0x00,                   /* date format: month/day/year */
  '$',  0x00, 0x00, 0x00, 0x00, /* currency symbol */
  ',',  0x00,                   /* thousands separator */
  '.',  0x00,                   /* decimal separator */
  '/',  0x00,                   /* date separator */
  ':',  0x00,                   /* time separator */
  0x00,                         /* currency format flags */
  0x02,                         /* currency digits after decimal */
  0x00,                         /* 12-hour clock */
  0x00, 0x00, 0x00, 0x00,       /* case-map call address */
  ',',  0x00,                   /* list separator */
};
