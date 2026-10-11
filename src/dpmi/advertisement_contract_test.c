#include "advertisement.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  DazeDpmiHostAdvertisement advertisement = {.ax = 0xa5a5};
  const DazeDpmiHostAdvertisement before = advertisement;
  if (daze_dpmi_host_advertisement_build(NULL, &advertisement) != 0 ||
      memcmp(&advertisement, &before, sizeof(advertisement)) != 0)
    return 1;
  const DazeDpmiHostAdvertisementInput input = {
    .installed = 1,
    .flags = 1,
    .processor = 3,
    .major = 0,
    .minor = 0x5a,
    .private_data_paragraphs = 0,
    .entry_segment = 0x0200,
    .entry_offset = 0,
  };
  uint16_t windows_ax = 0;
  int carry = 1;
  if (!daze_dpmi_host_advertisement_build(&input, &advertisement) || advertisement.ax != 0 ||
      advertisement.bx != 1 || advertisement.cx != 3 || advertisement.dx != 0x005a ||
      advertisement.si != 0 || advertisement.es != 0x0200 || advertisement.di != 0 ||
      advertisement.carry != 0 ||
      !daze_dpmi_host_windows_reply(&advertisement, &windows_ax, &carry) || windows_ax != 1 ||
      carry != 0)
    return 1;
  DazeDpmiHostAdvertisementInput invalid = input;
  const DazeDpmiHostAdvertisement valid = advertisement;
  assert(!daze_dpmi_host_advertisement_build(&input, NULL));
  for (int variant = 0; variant < 5; ++variant) {
    invalid = input;
    switch (variant) {
    case 0:
      invalid.installed = 0;
      break;
    case 1:
      invalid.flags = 2;
      break;
    case 2:
      invalid.processor = 1;
      break;
    case 3:
      invalid.processor = 5;
      break;
    case 4:
      invalid.entry_segment = 0;
      break;
    }
    assert(!daze_dpmi_host_advertisement_build(&invalid, &advertisement) &&
           memcmp(&advertisement, &valid, sizeof(valid)) == 0);
  }
  invalid = input;
  invalid.processor = 4;
  invalid.major = 1;
  invalid.private_data_paragraphs = 16;
  invalid.entry_offset = 0x1234;
  assert(daze_dpmi_host_advertisement_build(&invalid, &advertisement) && advertisement.cx == 4 &&
         advertisement.dx == 0x015a && advertisement.si == 16 && advertisement.di == 0x1234);
  windows_ax = 0xa5a5;
  carry = 7;
  assert(!daze_dpmi_host_windows_reply(NULL, &windows_ax, &carry));
  assert(!daze_dpmi_host_windows_reply(&advertisement, NULL, &carry));
  assert(!daze_dpmi_host_windows_reply(&advertisement, &windows_ax, NULL));
  advertisement.ax = 1;
  assert(!daze_dpmi_host_windows_reply(&advertisement, &windows_ax, &carry));
  advertisement.ax = 0;
  advertisement.carry = 1;
  assert(!daze_dpmi_host_windows_reply(&advertisement, &windows_ax, &carry));
  assert(windows_ax == 0xa5a5 && carry == 7);
  puts("DPMI host advertisement: passed");
  return 0;
}
