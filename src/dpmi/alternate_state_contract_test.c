#include "alternate_state.h"

#include <stdio.h>
#include <string.h>

static DpmiAlternateState valid_state(void) {
  DpmiAlternateState state = {0};
  state.eax = 0x0001;
  state.ebx = 0x0d73;
  state.ecx = 0xff00;
  state.edx = 0x0000;
  state.esi = 0x0042;
  state.edi = 0x0000;
  state.ebp = 0x7ff0;
  state.esp = 0x4b08;
  state.eip = 0x37b2;
  state.eflags = 0x3202;
  state.cs = 0x107f;
  state.ds = 0x1010;
  state.es = 0x1543;
  state.fs = 0x0700;
  state.gs = 0x0ff0;
  state.ss = 0x1010;
  return state;
}

/* Byte-distinct record: every 32-bit and 16-bit field carries a unique
 * marker so its encoded position in the wire image is provable. EIP and ESP
 * stay within 16 bits (validity rule) and reserved stays zero (validity
 * rule). */
static DpmiAlternateState byte_distinct_state(void) {
  DpmiAlternateState state = {0};
  state.eax = 0xDEBCCDAB;
  state.ebx = 0xF0EF2301;
  state.ecx = 0x9A896745;
  state.edx = 0x12F0DEBC;
  state.esi = 0x9A785634;
  state.edi = 0x3322110F;
  state.ebp = 0x77665544;
  state.esp = 0x8182;
  state.eip = 0x8384;
  state.eflags = 0xC8B7A695;
  state.cs = 0xD9DA;
  state.ds = 0xEBEC;
  state.es = 0xFDFE;
  state.fs = 0x0102;
  state.gs = 0x0304;
  state.ss = 0x0506;
  return state;
}

/* The little-endian wire image of byte_distinct_state(), written out in full
 * so every byte position is pinned against the documented layout. */
static const uint8_t expected_image[DAZE_DPMI_ALTERNATE_STATE_SIZE] = {
  0xab, 0xcd, 0xbc, 0xde, /* eax   0x00 */
  0x01, 0x23, 0xef, 0xf0, /* ebx   0x04 */
  0x45, 0x67, 0x89, 0x9a, /* ecx   0x08 */
  0xbc, 0xde, 0xf0, 0x12, /* edx   0x0c */
  0x34, 0x56, 0x78, 0x9a, /* esi   0x10 */
  0x0f, 0x11, 0x22, 0x33, /* edi   0x14 */
  0x44, 0x55, 0x66, 0x77, /* ebp   0x18 */
  0x82, 0x81, 0x00, 0x00, /* esp   0x1c */
  0x84, 0x83, 0x00, 0x00, /* eip   0x20 */
  0x95, 0xa6, 0xb7, 0xc8, /* eflags 0x24 */
  0xda, 0xd9,             /* cs    0x28 */
  0xec, 0xeb,             /* ds    0x2a */
  0xfe, 0xfd,             /* es    0x2c */
  0x02, 0x01,             /* fs    0x2e */
  0x04, 0x03,             /* gs    0x30 */
  0x06, 0x05,             /* ss    0x32 */
  0x00, 0x00, 0x00, 0x00, /*            0x34 */
  0x00, 0x00, 0x00, 0x00, /* reserved    0x38 */
};

static int expect_valid(const DpmiAlternateState *state, const char *what) {
  if (daze_dpmi_alternate_state_valid(state)) return 0;
  fprintf(stderr, "expected valid %s\n", what);
  return 1;
}

static int expect_invalid(const DpmiAlternateState *state, const char *what) {
  if (!daze_dpmi_alternate_state_valid(state)) return 0;
  fprintf(stderr, "expected invalid %s\n", what);
  return 1;
}

static int expect_exact_image(const DpmiAlternateState *state,
                              const uint8_t expected[DAZE_DPMI_ALTERNATE_STATE_SIZE],
                              const char *what) {
  uint8_t image[DAZE_DPMI_ALTERNATE_STATE_SIZE];
  if (!daze_dpmi_alternate_state_pack(state, image)) {
    fprintf(stderr, "pack failed for %s\n", what);
    return 1;
  }
  if (memcmp(image, expected, sizeof(image)) != 0) {
    fprintf(stderr, "wire image mismatch for %s\n", what);
    return 1;
  }
  return 0;
}

static int expect_round_trip(const DpmiAlternateState *state, const char *what) {
  uint8_t image[DAZE_DPMI_ALTERNATE_STATE_SIZE];
  DpmiAlternateState decoded = {0};
  uint8_t reencoded[DAZE_DPMI_ALTERNATE_STATE_SIZE];
  if (!daze_dpmi_alternate_state_pack(state, image)) {
    fprintf(stderr, "pack failed for %s\n", what);
    return 1;
  }
  if (!daze_dpmi_alternate_state_unpack(image, &decoded)) {
    fprintf(stderr, "unpack failed for %s\n", what);
    return 1;
  }
  if (memcmp(&decoded, state, sizeof(decoded)) != 0) {
    fprintf(stderr, "round trip changed %s\n", what);
    return 1;
  }
  if (!daze_dpmi_alternate_state_pack(&decoded, reencoded) ||
      memcmp(reencoded, image, sizeof(reencoded)) != 0) {
    fprintf(stderr, "re-encode changed %s\n", what);
    return 1;
  }
  return 0;
}

static int expect_unpack_rejects(const uint8_t image[DAZE_DPMI_ALTERNATE_STATE_SIZE],
                                 const char *what) {
  DpmiAlternateState decoded = {0};
  if (daze_dpmi_alternate_state_unpack(image, &decoded)) {
    fprintf(stderr, "expected unpack to reject %s\n", what);
    return 1;
  }
  return 0;
}

static int expect_zero(int result, const char *what) {
  if (!result) return 0;
  fprintf(stderr, "expected call to fail: %s\n", what);
  return 1;
}

int main(void) {
  DpmiAlternateState state = valid_state();
  DpmiAlternateState distinct = byte_distinct_state();
  uint8_t image[DAZE_DPMI_ALTERNATE_STATE_SIZE];
  int failures = 0;

  failures += expect_valid(&state, "baseline");

  failures += expect_invalid(NULL, "NULL record");

  state = valid_state();
  state.eip = UINT16_MAX;
  failures += expect_valid(&state, "EIP at 16-bit boundary");
  state = valid_state();
  state.eip = UINT16_MAX + 1;
  failures += expect_invalid(&state, "EIP beyond 16 bits");

  state = valid_state();
  state.esp = UINT16_MAX;
  failures += expect_valid(&state, "ESP at 16-bit boundary");
  state = valid_state();
  state.esp = UINT16_MAX + 1;
  failures += expect_invalid(&state, "ESP beyond 16 bits");

  state = valid_state();
  state.cs = 0;
  failures += expect_invalid(&state, "zero CS");
  state = valid_state();
  state.ds = 0;
  failures += expect_invalid(&state, "zero DS");
  state = valid_state();
  state.ss = 0;
  failures += expect_invalid(&state, "zero SS");

  for (size_t index = 0; index < sizeof(state.reserved); ++index) {
    state = valid_state();
    state.reserved[index] = 0x01;
    failures += expect_invalid(&state, "nonzero reserved byte");
  }

  failures += expect_valid(&distinct, "byte-distinct state");
  failures += expect_exact_image(&distinct, expected_image, "byte-distinct state");
  failures += expect_round_trip(&distinct, "byte-distinct state");
  DpmiAlternateState baseline = valid_state();
  failures += expect_round_trip(&baseline, "baseline");

  DpmiAlternateState minimal = {0};
  minimal.esp = 0x0001;
  minimal.eip = UINT16_MAX;
  minimal.cs = 1;
  minimal.ds = 1;
  minimal.ss = 1;
  failures += expect_round_trip(&minimal, "minimal valid");

  failures += expect_zero(daze_dpmi_alternate_state_pack(NULL, image), "pack NULL state");
  failures += expect_zero(daze_dpmi_alternate_state_pack(&distinct, NULL), "pack NULL image");
  failures +=
    expect_zero(daze_dpmi_alternate_state_unpack(expected_image, NULL), "unpack NULL state");
  failures += expect_zero(daze_dpmi_alternate_state_unpack(NULL, &state), "unpack NULL image");

  memcpy(image, expected_image, sizeof(image));
  image[0x28] = 0;
  image[0x29] = 0;
  failures += expect_unpack_rejects(image, "zero-CS wire image");
  memcpy(image, expected_image, sizeof(image));
  image[0x23] = 0x01;
  failures += expect_unpack_rejects(image, "EIP beyond 16 bits");
  for (size_t index = 0; index < 8; ++index) {
    memcpy(image, expected_image, sizeof(image));
    image[0x34 + index] = 0x5a;
    failures += expect_unpack_rejects(image, "nonzero reserved wire byte");
  }

  state = byte_distinct_state();
  state.reserved[3] = 0x5a;
  if (!daze_dpmi_alternate_state_pack(&state, image)) {
    fprintf(stderr, "pack failed for invalid-state serialization\n");
    ++failures;
  } else if (image[0x37] != 0x5a) {
    fprintf(stderr, "reserved byte not encoded at 0x37\n");
    ++failures;
  } else {
    failures += expect_unpack_rejects(image, "invalid-state pack image");
  }

  if (failures) {
    fprintf(stderr, "dpmi alternate-state contract: failed (%d)\n", failures);
    return 1;
  }
  fprintf(stderr, "dpmi alternate-state contract: passed\n");
  return 0;
}
