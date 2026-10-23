#include "descriptor.h"
#include "linear_memory.h"

#include <stdio.h>

static int sets_base(const uint8_t original[8], uint32_t base, const uint8_t expected[8]) {
  uint8_t descriptor[8];
  for (size_t index = 0; index < 8; ++index)
    descriptor[index] = original[index];
  daze_dpmi_descriptor_set_base(descriptor, base);
  for (size_t index = 0; index < 8; ++index) {
    if (descriptor[index] != expected[index]) return 0;
  }
  return 1;
}

static int sets_limit(const uint8_t original[8], uint32_t limit, const uint8_t expected[8]) {
  uint8_t descriptor[8];
  for (size_t index = 0; index < 8; ++index)
    descriptor[index] = original[index];
  if (!daze_dpmi_descriptor_set_limit(descriptor, limit)) return 0;
  for (size_t index = 0; index < 8; ++index) {
    if (descriptor[index] != expected[index]) return 0;
  }
  return 1;
}

static int rejects_limit(const uint8_t original[8], uint32_t limit) {
  uint8_t descriptor[8];
  for (size_t index = 0; index < 8; ++index)
    descriptor[index] = original[index];
  if (daze_dpmi_descriptor_set_limit(descriptor, limit)) return 0;
  for (size_t index = 0; index < 8; ++index) {
    if (descriptor[index] != original[index]) return 0;
  }
  return 1;
}

static int sets_access(const uint8_t original[8], uint16_t rights, const uint8_t expected[8]) {
  uint8_t descriptor[8];
  for (size_t index = 0; index < 8; ++index)
    descriptor[index] = original[index];
  daze_dpmi_descriptor_set_access(descriptor, rights);
  for (size_t index = 0; index < 8; ++index) {
    if (descriptor[index] != expected[index]) return 0;
  }
  return 1;
}

int main(void) {
  int pass = 1;

  uint8_t encoded[8] = {0};
  daze_dpmi_descriptor_encode(encoded, 0x12345678u, 0x000ABCDEu, 0x9b, 0x0c);
  const uint8_t encoded_expected[8] = {0xde, 0xbc, 0x78, 0x56, 0x34, 0x9b, 0xca, 0x12};
  for (size_t index = 0; index < sizeof(encoded); ++index)
    pass = pass && encoded[index] == encoded_expected[index];

  /* All-distinct bytes expose unintended changes outside the base fields. */
  const uint8_t lanes_original[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  const uint8_t lanes_expected[8] = {0x11, 0x22, 0x78, 0x56, 0x34, 0x66, 0x77, 0x12};
  pass = pass && sets_base(lanes_original, 0x12345678u, lanes_expected);

  /* Feed the measured ASPSX 0501h allocation base into 0007h to test the service chain. */
  DazeDpmiLinearMemory chain_memory;
  DazeDpmiLinearAllocateResult chain_result;
  daze_dpmi_linear_memory_init(&chain_memory, 0x00050000u, 0x007f0000u);
  daze_dpmi_linear_memory_allocate_result(&chain_memory, 0x00015000u, &chain_result);
  pass = pass && chain_result.success && chain_result.dpmi_error == 0 &&
         chain_result.base == 0x00050000u && chain_result.handle == 1;
  struct {
    const char *selector;
    const uint8_t pre[8];
    const uint8_t post[8];
  } const chain[] = {
    {"0094",
     {0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0xC0, 0x00},
     {0x00, 0x00, 0x00, 0x00, 0x05, 0x97, 0xC0, 0x00}},
    {"009C",
     {0x00, 0x00, 0x00, 0x00, 0x00, 0x9B, 0xC0, 0x00},
     {0x00, 0x00, 0x00, 0x00, 0x05, 0x9B, 0xC0, 0x00}},
    {"00A4",
     {0x7F, 0x00, 0x00, 0x00, 0x00, 0x97, 0x40, 0x00},
     {0x7F, 0x00, 0x00, 0x00, 0x05, 0x97, 0x40, 0x00}},
  };
  for (size_t index = 0; index < sizeof(chain) / sizeof(chain[0]); ++index) {
    pass = pass && sets_base(chain[index].pre, chain_result.base, chain[index].post);
  }

  /* All-distinct bytes expose damage outside limit/G fields, including D/B, L, and AVL. */
  const uint8_t limit_lanes_original[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  const uint8_t limit_lanes_expected[8] = {0xDE, 0xBC, 0x33, 0x44, 0x55, 0x66, 0x7A, 0x88};
  pass = pass && sets_limit(limit_lanes_original, 0x000ABCDEu, limit_lanes_expected);

  /* Real ASPSX selector 008Ch: FFFFFFFFh is page-granular, so bytes 0-1
   * become 0xFFFF, byte-6 low nibble becomes 0xF, and G is set. */
  const uint8_t aspsx_008c_limit_original[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0xC0, 0x00};
  const uint8_t aspsx_008c_limit_expected[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x93, 0xCF, 0x00};
  pass = pass && sets_limit(aspsx_008c_limit_original, 0xFFFFFFFFu, aspsx_008c_limit_expected);

  /* Real ASPSX selector 00A4h: 0000007Fh is a direct byte-granular update
   * that clears G while retaining base 00050000h and access 0x97. */
  const uint8_t aspsx_00a4_limit_original[8] = {0x7F, 0x00, 0x00, 0x00, 0x05, 0x97, 0xCF, 0x00};
  const uint8_t aspsx_00a4_limit_expected[8] = {0x7F, 0x00, 0x00, 0x00, 0x05, 0x97, 0x40, 0x00};
  pass = pass && sets_limit(aspsx_00a4_limit_original, 0x0000007Fu, aspsx_00a4_limit_expected);

  /* 00100000h is larger than byte-granular but does not end on a page
   * boundary: rejected, and the all-distinct descriptor stays identical. */
  pass = pass && rejects_limit(limit_lanes_original, 0x00100000u);

  /* All-distinct bytes expose damage outside access/type and the high flags nibble. */
  const uint8_t access_lanes_original[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  const uint8_t access_lanes_expected[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x9B, 0xC7, 0x88};
  pass = pass && sets_access(access_lanes_original, 0xC09Bu, access_lanes_expected);

  /* Real ASPSX shape, selector 009Ch: rights C09Bh write access 0x9B and
   * flags 0xC0 while 009C's limit 0007Fh (bytes 0-1) and base 00050000h
   * (bytes 2-4,7) stay in place. */
  const uint8_t aspsx_009c_pre[8] = {0x7F, 0x00, 0x00, 0x00, 0x05, 0x97, 0x40, 0x00};
  const uint8_t aspsx_009c_post[8] = {0x7F, 0x00, 0x00, 0x00, 0x05, 0x9B, 0xC0, 0x00};
  pass = pass && sets_access(aspsx_009c_pre, 0xC09Bu, aspsx_009c_post);

  /* Real ASPSX selector 008Ch: rights C093h write access 0x93 and flags
   * 0xC0; the observed post-image has no base or limit bits set. */
  const uint8_t aspsx_008c_pre[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x9B, 0xC0, 0x00};
  const uint8_t aspsx_008c_post[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0xC0, 0x00};
  pass = pass && sets_access(aspsx_008c_pre, 0xC093u, aspsx_008c_post);

  /* Real ASPSX shape, selectors 0094h and 00A4h: rights C097h write access
   * 0x97 and flags 0xC0 while the byte-granular limit 007Fh (bytes 0-1,
   * byte-6 low nibble 0) is preserved. */
  const uint8_t aspsx_0094_00a4_pre[8] = {0x7F, 0x00, 0x00, 0x00, 0x00, 0x9B, 0x40, 0x00};
  const uint8_t aspsx_0094_00a4_post[8] = {0x7F, 0x00, 0x00, 0x00, 0x00, 0x97, 0xC0, 0x00};
  pass = pass && sets_access(aspsx_0094_00a4_pre, 0xC097u, aspsx_0094_00a4_post);

  fprintf(stderr, "DPMI descriptor contract test: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
