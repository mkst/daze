#include "country.h"
#include "int21_service.h"

#include <stdio.h>
#include <string.h>

typedef struct {
  uint8_t bytes[256];
  int fail_write;
  uint16_t segment;
  uint16_t offset;
  size_t size;
} Memory;

static int memory_write(void *context, uint16_t segment, uint16_t offset, const void *bytes,
                        size_t size) {
  Memory *memory = context;
  if (memory == NULL || memory->fail_write || segment != 0x0600 ||
      size > sizeof(memory->bytes) - offset)
    return 0;
  memcpy(memory->bytes + offset, bytes, size);
  memory->segment = segment;
  memory->offset = offset;
  memory->size = size;
  return 1;
}

static const uint8_t kExpected[DAZE_DOS_COUNTRY_TABLE_SIZE] = {
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

int main(void) {
  if (DAZE_DOS_COUNTRY_TABLE_SIZE != 24u ||
      memcmp(daze_dos_country_usa, kExpected, sizeof(kExpected)) != 0) {
    fprintf(stderr, "country: USA table mismatch\n");
    return 1;
  }
  fprintf(stderr, "country: USA table matches documented layout\n");

  Memory memory;
  memset(&memory, 0xa5, sizeof(memory));
  memory.fail_write = 0;
  DazeDosInt21Context context = {
    .guest_memory = {.context = &memory, .write = memory_write},
  };
  DazeDosInt21Request request = {.ax = 0x3800, .ds = 0x0600, .dx = 0x10};
  DazeDosInt21Result result;
  if (daze_dos_int21_dispatch(&context, &request, &result) != DAZE_DOS_INT21_DISPATCH_OK ||
      result.disposition != DAZE_DOS_INT21_HANDLED ||
      result.register_write_mask != DAZE_DOS_INT21_REG_BX || result.bx != 1 ||
      result.flag_write_mask != DAZE_DOS_INT21_FLAG_CF ||
      (result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0 || memory.segment != 0x0600 ||
      memory.offset != 0x10 || memory.size != DAZE_DOS_COUNTRY_TABLE_SIZE ||
      memcmp(memory.bytes + 0x10, kExpected, sizeof(kExpected)) != 0) {
    fprintf(stderr, "country: AL=00 did not fill DS:DX with BX=1 carry-clear\n");
    return 1;
  }
  for (size_t index = 0; index < sizeof(memory.bytes); ++index) {
    if (index >= 0x10 && index < 0x10 + DAZE_DOS_COUNTRY_TABLE_SIZE) continue;
    if (memory.bytes[index] != 0xa5) {
      fprintf(stderr, "country: write escaped the 24-byte table at %zu\n", index);
      return 1;
    }
  }
  fprintf(stderr, "country: AL=00 fills 24 bytes, preserves surroundings\n");

  memset(&memory, 0xa5, sizeof(memory));
  memory.fail_write = 0;
  request.ax = 0x3801;
  if (daze_dos_int21_dispatch(&context, &request, &result) != DAZE_DOS_INT21_DISPATCH_OK ||
      result.disposition != DAZE_DOS_INT21_UNSUPPORTED || result.register_write_mask != 0 ||
      result.flag_write_mask != 0 || memory.bytes[0x10] != 0xa5) {
    fprintf(stderr, "country: nonzero AL must stay unsupported without writes\n");
    return 1;
  }
  fprintf(stderr, "country: nonzero AL unsupported\n");

  memset(&memory, 0, sizeof(memory));
  memory.fail_write = 1;
  request.ax = 0x3800;
  if (daze_dos_int21_dispatch(&context, &request, &result) !=
      DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE) {
    fprintf(stderr, "country: guest write failure must report memory failure\n");
    return 1;
  }
  fprintf(stderr, "country: guest write failure reported\n");

  const DazeDosInt21Context no_memory = {0};
  if (daze_dos_int21_dispatch(&no_memory, &request, &result) !=
      DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE) {
    fprintf(stderr, "country: missing write callback must report memory failure\n");
    return 1;
  }
  fprintf(stderr, "country: missing write callback reported\n");
  return 0;
}
