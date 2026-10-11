#include "fcb.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  uint8_t fcb[16];
  size_t consumed = 0;
  uint8_t result = 0xff;
  const uint8_t path[] = "C:\\GO32.EXE";
  const uint8_t expected[] = {3,   'G', 'O', '3', '2', ' ', ' ', ' ',
                              ' ', 'E', 'X', 'E', ' ', ' ', ' ', ' '};
  if (!daze_dos_fcb_parse(path, sizeof(path), 1, fcb, &consumed, &result) || result != 0 ||
      consumed != sizeof(path) - 1 || memcmp(fcb, expected, sizeof(fcb)) != 0) {
    fprintf(stderr, "plain FCB parse failed\n");
    return 1;
  }
  const uint8_t wildcard[] = "*.C";
  if (!daze_dos_fcb_parse(wildcard, sizeof(wildcard), 0, fcb, &consumed, &result) || result != 1 ||
      memcmp(fcb + 1, "????????C  ", 11) != 0) {
    fprintf(stderr, "wildcard FCB parse failed\n");
    return 1;
  }
  const uint8_t invalid[] = "1:BAD";
  if (!daze_dos_fcb_parse(invalid, sizeof(invalid), 0, fcb, &consumed, &result) || result != 0xff) {
    fprintf(stderr, "invalid-drive FCB parse failed\n");
    return 1;
  }
  memset(fcb, 0xa5, sizeof(fcb));
  consumed = 123;
  result = 42;
  uint8_t before[16];
  memcpy(before, fcb, sizeof(before));
  assert(!daze_dos_fcb_parse(NULL, 1, 0, fcb, &consumed, &result));
  assert(!daze_dos_fcb_parse(path, 0, 0, fcb, &consumed, &result));
  assert(!daze_dos_fcb_parse(path, sizeof(path), 0, NULL, &consumed, &result));
  assert(!daze_dos_fcb_parse(path, sizeof(path), 0, fcb, NULL, &result));
  assert(!daze_dos_fcb_parse(path, sizeof(path), 0, fcb, &consumed, NULL));
  assert(!daze_dos_fcb_parse(path, sizeof(path) - 1, 0, fcb, &consumed, &result));
  assert(memcmp(before, fcb, sizeof(before)) == 0 && consumed == 123 && result == 42);
  const uint8_t long_name[] = "d:/dir/abcdefghijk.12345\r";
  assert(daze_dos_fcb_parse(long_name, sizeof(long_name), 0, fcb, &consumed, &result) &&
         result == 0 && consumed == sizeof(long_name) - 2 && fcb[0] == 4 &&
         memcmp(fcb + 1, "ABCDEFGH123", 11) == 0);
  const uint8_t question[] = "ab?.?o";
  assert(daze_dos_fcb_parse(question, sizeof(question), 0, fcb, &consumed, &result) &&
         result == 1 && memcmp(fcb + 1, "AB?     ?O ", 11) == 0);
  const uint8_t tabs[] = "\t\tfoo.asm";
  assert(daze_dos_fcb_parse(tabs, sizeof(tabs), 1, fcb, &consumed, &result) && result == 0 &&
         consumed == sizeof(tabs) - 1 && memcmp(fcb + 1, "FOO     ASM", 11) == 0);
  return 0;
}
