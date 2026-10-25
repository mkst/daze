#include "bios_adapter.h"
#include "byte_order.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <string.h>

int main(void) {
  const uint16_t cases[][6] = {
    {0x11, 0xabcd, 0x9876, 0x20, 0x9876, 0x3456},
    {0x10, 0x0fab, 0x9876, 0x5003, 0x76, 0x3456},
    {0x10, 0x1200, 0x9810, 0x1200, 3, 1},
    {0x1a, 0x00ab, 0x9876, 0, 0x9876, 0},
  };
  uint8_t record[24], before[24], mailbox[16], expected[16];
  for (unsigned carry = 0; carry < 2; ++carry) {
    for (unsigned index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
      for (unsigned word = 0; word < 12; ++word)
        daze_write_u16(record + word * 2, (uint16_t)(0x1234 + word * 0x111));
      daze_write_u16(record, cases[index][1]);
      daze_write_u16(record + 2, cases[index][2]);
      daze_write_u16(record + 4, 0x3456);
      daze_write_u16(record + 16, cases[index][0]);
      daze_write_u16(record + 22, (uint16_t)(0x0ed6 | carry));
      memcpy(before, record, sizeof(record));
      const unsigned offsets[] = {0, 2, 4, 6, 12, 14, 10, 22};
      for (unsigned word = 0; word < 8; ++word)
        memcpy(expected + word * 2, record + offsets[word], 2);
      daze_write_u16(expected, cases[index][3]);
      daze_write_u16(expected + 2, cases[index][4]);
      daze_write_u16(expected + 4, cases[index][5]);
      if (index == 3) daze_write_u16(expected + 6, 0);
      daze_write_u16(expected + 14, 0x0ed6);
      memset(mailbox, 0xa5, sizeof(mailbox));
      assert(daze_kvm_bios_dispatch(record, mailbox) == DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED);
      assert(memcmp(mailbox, expected, sizeof(mailbox)) == 0);
      assert(memcmp(record, before, sizeof(record)) == 0);
    }
  }
  const uint16_t unsupported[][3] = {
    {0x60, 0, 0},         {0x1a, 0x0100, 0}, {0x10, 0x1201, 0x10}, {0x10, 0x1200, 0x11},
    {0x10, 0x0000, 0x10}, {0x67, 0xde00, 0}, {0x15, 0xc000, 0},
  };
  for (unsigned index = 0; index < sizeof(unsupported) / sizeof(unsupported[0]); ++index) {
    daze_write_u16(record + 16, unsupported[index][0]);
    daze_write_u16(record, unsupported[index][1]);
    daze_write_u16(record + 2, unsupported[index][2]);
    memcpy(before, record, sizeof(record));
    memset(mailbox, 0xa5, sizeof(mailbox));
    memcpy(expected, mailbox, sizeof(mailbox));
    assert(daze_kvm_bios_dispatch(record, mailbox) == DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED);
    assert(memcmp(expected, mailbox, sizeof(mailbox)) == 0);
    assert(memcmp(before, record, sizeof(record)) == 0);
  }
  assert(daze_kvm_bios_dispatch(NULL, mailbox) == DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
  assert(memcmp(expected, mailbox, sizeof(mailbox)) == 0);
  assert(daze_kvm_bios_dispatch(record, NULL) == DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
  return 0;
}
