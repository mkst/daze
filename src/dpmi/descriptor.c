#include "descriptor.h"

void daze_dpmi_descriptor_encode(uint8_t descriptor[8], uint32_t base, uint32_t limit,
                                 uint8_t access, uint8_t flags) {
  descriptor[0] = (uint8_t)limit;
  descriptor[1] = (uint8_t)(limit >> 8);
  descriptor[2] = (uint8_t)base;
  descriptor[3] = (uint8_t)(base >> 8);
  descriptor[4] = (uint8_t)(base >> 16);
  descriptor[5] = access;
  descriptor[6] = (uint8_t)((limit >> 16) & 0x0fu) | (uint8_t)(flags << 4);
  descriptor[7] = (uint8_t)(base >> 24);
}

void daze_dpmi_descriptor_set_base(uint8_t descriptor[8], uint32_t base) {
  descriptor[2] = (uint8_t)base;
  descriptor[3] = (uint8_t)(base >> 8);
  descriptor[4] = (uint8_t)(base >> 16);
  descriptor[7] = (uint8_t)(base >> 24);
}

int daze_dpmi_descriptor_set_limit(uint8_t descriptor[8], uint32_t limit) {
  if (limit > 0x000fffffu && (limit & 0xfffu) != 0xfffu) return 0;
  const int granular = limit > 0x000fffffu;
  const uint32_t field = granular ? limit >> 12 : limit;
  descriptor[0] = (uint8_t)field;
  descriptor[1] = (uint8_t)(field >> 8);
  descriptor[6] =
    (uint8_t)((descriptor[6] & 0x70u) | (granular ? 0x80u : 0u) | (uint8_t)((field >> 16) & 0x0fu));
  return 1;
}

void daze_dpmi_descriptor_set_access(uint8_t descriptor[8], uint16_t rights) {
  descriptor[5] = (uint8_t)rights;
  descriptor[6] = (uint8_t)((descriptor[6] & 0x0fu) | (rights & 0xf000u) >> 8);
}
