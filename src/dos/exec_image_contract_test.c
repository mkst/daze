#include "exec_image.h"

#include <stdlib.h>
#include <string.h>

#include "byte_order.h"

static int rejected_ranges(void) {
  uint8_t bytes[64] = {0};
  DazeImage image = {.bytes = bytes, .size = sizeof(bytes)};
  const DazeMzHeader cases[] = {
    {.image_offset = SIZE_MAX},
    {.image_offset = 60, .image_size = SIZE_MAX},
    {.relocation_offset = 65},
    {.relocation_offset = 63, .relocations = 1},
    {.relocation_offset = 28, .relocations = UINT16_MAX},
    {.image_offset = 32, .image_size = 17},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    uint8_t *prepared = NULL;
    size_t size = 0xa5a5;
    if (daze_dos_exec_image_prepare(&image, &cases[i], 0x3010, 0x30110, &prepared, &size) ||
        prepared != NULL || size != 0xa5a5) {
      free(prepared);
      return 0;
    }
  }
  const DazeMzHeader header = {.image_offset = 32, .image_size = 16};
  uint8_t *prepared = NULL;
  size_t size = 0xa5a5;
  if (daze_dos_exec_image_prepare(NULL, &header, 0, 64, &prepared, &size) ||
      daze_dos_exec_image_prepare(&image, NULL, 0, 64, &prepared, &size) ||
      daze_dos_exec_image_prepare(&image, &header, 0, 64, NULL, &size) ||
      daze_dos_exec_image_prepare(&image, &header, 0, 64, &prepared, NULL) ||
      daze_dos_exec_image_prepare(&image, &header, 0x3010, 0x300ff, &prepared, &size) ||
      prepared != NULL || size != 0xa5a5)
    return 0;
  image.bytes = NULL;
  if (daze_dos_exec_image_prepare(&image, &header, 0, 64, &prepared, &size) || prepared != NULL ||
      size != 0xa5a5)
    return 0;
  image.bytes = bytes;
  if (!daze_dos_exec_image_prepare(&image, &header, 0x3010, 0x30110, &prepared, &size)) return 0;
  const int pass = size == 16 && memcmp(prepared, bytes + 32, size) == 0;
  free(prepared);
  return pass;
}

int main(void) {
  if (!rejected_ranges()) return 1;
  uint8_t bytes[64] = {0};
  DazeImage image = {.bytes = bytes, .size = sizeof(bytes)};
  DazeMzHeader header = {
    .relocations = 1, .relocation_offset = 0x1c, .image_offset = 0x20, .image_size = 16};
  uint8_t *prepared = NULL;
  size_t prepared_size = 0;
  daze_write_u16(bytes + 0x1c, 4);
  daze_write_u16(bytes + 0x1e, 0);
  daze_write_u16(bytes + 0x24, 0x1234);
  if (!daze_dos_exec_image_prepare(&image, &header, 0x3010, 0x100000, &prepared, &prepared_size) ||
      prepared_size != 16 || prepared[0] != 0 || prepared[4] != 0x44 || prepared[5] != 0x42) {
    free(prepared);
    return 1;
  }
  free(prepared);
  header.relocations = 1;
  daze_write_u16(bytes + 0x1c, 15);
  if (daze_dos_exec_image_prepare(&image, &header, 0x3010, 0x100000, &prepared, &prepared_size)) {
    free(prepared);
    return 1;
  }
  daze_write_u16(bytes + 0x1c, 0);
  header.image_offset = 60;
  if (daze_dos_exec_image_prepare(&image, &header, 0x3010, 0x100000, &prepared, &prepared_size)) {
    free(prepared);
    return 1;
  }
  header.image_offset = 0x20;
  header.image_size = 16;
  if (daze_dos_exec_image_prepare(&image, &header, 0xffff, 0xfffff, &prepared, &prepared_size)) {
    free(prepared);
    return 1;
  }
  return 0;
}
