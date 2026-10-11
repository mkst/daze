#include "advertisement.h"

#include <stddef.h>

int daze_dpmi_host_advertisement_build(const DazeDpmiHostAdvertisementInput *input,
                                       DazeDpmiHostAdvertisement *output) {
  if (input == NULL || output == NULL || !input->installed || (input->flags & 1u) == 0 ||
      input->processor < 2 || input->processor > 4 || input->entry_segment == 0)
    return 0;
  const DazeDpmiHostAdvertisement built = {
    .ax = 0,
    .bx = input->flags,
    .cx = input->processor,
    .dx = (uint16_t)((uint16_t)input->major << 8 | input->minor),
    .si = input->private_data_paragraphs,
    .es = input->entry_segment,
    .di = input->entry_offset,
    .carry = 0,
  };
  *output = built;
  return 1;
}

int daze_dpmi_host_windows_reply(const DazeDpmiHostAdvertisement *advertisement, uint16_t *ax,
                                 int *carry) {
  if (advertisement == NULL || ax == NULL || carry == NULL || advertisement->ax != 0 ||
      advertisement->carry != 0)
    return 0;
  *ax = 1;
  *carry = 0;
  return 1;
}
