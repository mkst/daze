#ifndef DAZE_DPMI_HOST_ADVERTISEMENT_H
#define DAZE_DPMI_HOST_ADVERTISEMENT_H

#include <stdint.h>

typedef struct {
  int installed;
  uint16_t flags;
  uint8_t processor, major, minor;
  uint16_t private_data_paragraphs;
  uint16_t entry_segment, entry_offset;
} DazeDpmiHostAdvertisementInput;

typedef struct {
  uint16_t ax, bx, cx, dx, si, es, di;
  int carry;
} DazeDpmiHostAdvertisement;

/* For INT 2Fh/1687h, the backend supplies the entry pointer only after
 * installing its callable trampoline. */
int daze_dpmi_host_advertisement_build(const DazeDpmiHostAdvertisementInput *input,
                                       DazeDpmiHostAdvertisement *output);

/* INT 2Fh/1600h reports enhanced mode only for an installed DPMI host. */
int daze_dpmi_host_windows_reply(const DazeDpmiHostAdvertisement *advertisement, uint16_t *ax,
                                 int *carry);

#endif
